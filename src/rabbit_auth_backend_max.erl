%% The contents of this file are subject to the Mozilla Public License
%% Version 1.1 (the "License"); you may not use this file except in
%% compliance with the License. You may obtain a copy of the License
%% at http://www.mozilla.org/MPL/
%%
%% Software distributed under the License is distributed on an "AS IS"
%% basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
%% the License for the specific language governing rights and
%% limitations under the License.
%%
%% The Original Code is RabbitMQ HTTP authentication.
%%
%% The Initial Developer of the Original Code is VMware, Inc.
%% Copyright (c) 2007-2011 VMware, Inc.  All rights reserved.
%%

-module(rabbit_auth_backend_max).

-include_lib("rabbit_common/include/rabbit.hrl").
-behaviour(rabbit_auth_backend).

-export([description/0, q/1]).
-export([check_user_login/2, check_vhost_access/2, check_resource_access/3]).

%% httpc seems to get racy when using HTTP 1.1
-define(HTTPC_OPTS, [{version, "HTTP/1.0"}, {ssl,[{verify,0}]}]).

%%--------------------------------------------------------------------

description() ->
    [{name, <<"HTTP">>},
     {description, <<"HTTP authentication / authorisation">>}].

%%--------------------------------------------------------------------

%% *********************************************************************
%% *  User Authorization Callback Implementation
%% *  Routes the user and token (sent trough the password field)
%% *  trough the oauth check endpoint, and stores the token in
%% *  the user record field `impl` to be able to access it later
%% *  in the resource authorization step
%% *********************************************************************

check_user_login(Username, AuthProps) ->
    {password, Token} = lists:nth(1, AuthProps),
    %% Echoes login info
    %% io:format("Q: ~p~n", [AuthProps]),
    case oauth_check_token(binary_to_list(Username), binary_to_list(Token)) of
        false            -> {refused, "Denied by HTTP plugin", []};
        true           -> {ok, #user{username     = Username,
                                      tags         = [],
                                      auth_backend = ?MODULE,
                                      impl         = Token}};
        Other           -> {error, {bad_response, Other}}
    end.

%% *********************************************************************
%% *  VHost Authorization Callback Implementation
%% *  Not really doing anything here...
%% *********************************************************************

check_vhost_access(#user{username = _Username}, _VHost) ->
    true.

%% *********************************************************************
%% *  Resource Authorization Callback Implementation
%% *  Grant/check acces on all permissions to:
%% *  - `new` exchange
%% *  - Conversation exchanges
%% *  - Dynamically created queues
%% *  Deny access to everything else
%% *********************************************************************

check_resource_access(#user{username = Username, impl = Token},
                      #resource{kind = Type, name = Name},
                      _Permission) ->
    SName = binary_to_list(Name),
    SUsername = binary_to_list(Username),
    SubscribeExchange = SUsername ++ ".subscribe",
    PublishExchange = SUsername ++ ".publish",
    case Type of
        exchange -> case SName of
                        SubscribeExchange       -> true;
                        PublishExchange         -> true;
                        _                       -> false
                    end;
        queue    -> case string:substr(SName, 1, 7) of
                        "amq.gen"    -> true;
                        _            -> false
                    end
    end.

%%--------------------------------------------------------------------

%% *********************************************************************
%% *  Authorizes given user and token
%% *  trough the designated oauth server.
%% *  Returns true on valid token
%% *********************************************************************

oauth_check_token(OUsername, OToken) ->
    {DomainPath, Username} = extract_domain_and_user_from_auth(OUsername),
    {ok, OAuthServerBaseURL} = application:get_env(rabbitmq_auth_backend_max, oauth_server),
    StandardParams = [{scope,        "widgetcli"},
                      {username,     Username},
                      {access_token, OToken}],
    PHPDMParams = [{scope,       "widgetcli"},
                   {user_id,     Username},
                   {oauth_token, OToken}],
    {ok, OauthStandard} = application:get_env(rabbitmq_auth_backend_max, oauth_standard),
    case OauthStandard of
        "true"         -> Params = StandardParams;
        "false"        -> Params = PHPDMParams
    end,
    OAuthServer = OAuthServerBaseURL ++ DomainPath ++ "/checktoken",
    http_post(OAuthServer, [], q(Params)).


%% *********************************************************************
%% *  Authorizes given user on a given conversation
%% *  identified by the conected exchange
%% *  Checks that the exchange name is a valid Mongo ID
%% *  Otherwise asume that this is another exchange, and deny access
%% *********************************************************************

% check_user_can_access_conversation_exchange(UserName, OAuthToken, ExchangeName) ->
%     RegExp = "^[a-f0-9]{24}$",
%     case re:run(ExchangeName, RegExp) of
%         nomatch            -> false;
%         _                  -> max_get_conversation(UserName, OAuthToken, ExchangeName)
%     end.


%% *********************************************************************
%% *  Gets the response of trying to get a conversation's data
%% *  Prepare the endpoint url and headers and make the GET request
%% *********************************************************************

% max_get_conversation(User, Token, ConversationID) ->
%   {DomainPath, Username} = extract_domain_and_user_from_auth(User),
%   {ok, MaxServerBase} = application:get_env(rabbitmq_auth_backend_max, max_server),
%   ConversationsEndpoint = MaxServerBase ++ DomainPath ++ "/conversations/" ++ ConversationID,
%   io:format("Q: ~p~n", [ConversationsEndpoint]),
%   Headers = [
%     {"X-Oauth-Scope", "widgetcli"},
%     {"X-Oauth-Token", Token},
%     {"X-Oauth-Username", Username}],
%   http_get(ConversationsEndpoint, Headers).

%% *********************************************************************
%% *  Extracts the domain:user data in the received username
%% *  and constructs the domain path if present
%% *********************************************************************

extract_domain_and_user_from_auth(UserDomain) ->
    RegExp = "(?:([^:]+):)*(.*)",
    {match, [_, {Dstart, Dend}, {Nstart, _Nend}]} = re:run(UserDomain, RegExp),
    case Dstart of
        -1      -> DomainPath = "";
        _       -> DomainPath = "/" ++ string:substr(UserDomain, Dstart+1, Dend)
    end,
    {DomainPath, string:substr(UserDomain, Nstart+1)}.

%% *********************************************************************
%% *  Performs a GET request with optional custom headers
%% *  Returns true or false indicating the success code of the request
%% *********************************************************************

% http_get(Path, Headers) ->
%     URI = uri_parser:parse(Path, [{port, 80}]),
%     {host, Host} = lists:keyfind(host, 1, URI),
%     {port, Port} = lists:keyfind(port, 1, URI),
%     HostHdr = rabbit_misc:format("~s:~b", [Host, Port]),
%     case httpc:request(get, {Path, Headers ++ [{"Host", HostHdr}]}, ?HTTPC_OPTS, []) of
%         {ok, {{_HTTP, Code, _}, _Headers, _Body}} ->
%             case Code of
%                 200 -> true;
%                 _   -> false
%             end;
%         {error, _} = E ->
%             E
%     end.

%% *********************************************************************
%% *  Performs a POST request with optional custom headers
%% *  Returns true or false indicating the success code of the request
%% *********************************************************************

http_post(Path, Headers, Body) ->
    ssl:start(),
    URI = uri_parser:parse(Path, [{port, 80}]),
    {host, Host} = lists:keyfind(host, 1, URI),
    {port, Port} = lists:keyfind(port, 1, URI),
    HostHdr = rabbit_misc:format("~s:~b", [Host, Port]),
    case httpc:request(post, {Path, Headers ++ [{"Host", HostHdr}], "application/x-www-form-urlencoded", Body }, ?HTTPC_OPTS, []) of
        {ok, {{_HTTP, Code, _}, _Headers, _Body}} ->
            %% Echoes response code and body
            %% io:format("Q: ~p~n", [Code]),
            %% io:format("Q: ~p~n", [_Body]),
            case Code of
                200 -> true;
                _   -> false
            end;
        {error, _} = E ->
            E
    end.

%% *********************************************************************
%% *  Constructs s query string out of a list of parameters
%% *********************************************************************

q(Args) ->
    R = string:join([escape(K, V) || {K, V} <- Args], "&"),
    %%io:format("Q: ~p~n", [R]),
    R.

escape(K, V) ->
    atom_to_list(K) ++ "=" ++ mochiweb_util:quote_plus(V).

%%--------------------------------------------------------------------
