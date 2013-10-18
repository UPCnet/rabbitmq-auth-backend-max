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

-export([description/0, q/2]).
-export([check_user_login/2, check_vhost_access/2, check_resource_access/3]).

%% httpc seems to get racy when using HTTP 1.1
-define(HTTPC_OPTS, [{version, "HTTP/1.0"}, {ssl,[{verify,0}]}]).

%%--------------------------------------------------------------------

description() ->
    [{name, <<"HTTP">>},
     {description, <<"HTTP authentication / authorisation">>}].

%%--------------------------------------------------------------------

check_user_login(Username, AuthProps) ->
    {password, Token} = lists:nth(1, AuthProps),
    case oauth_check_token(Username, Token) of
        false            -> {refused, "Denied by HTTP plugin", []};
        true           -> {ok, #user{username     = Username,
                                      tags         = [],
                                      auth_backend = ?MODULE,
                                      impl         = Token}};
        Other           -> {error, {bad_response, Other}}
    end.

check_vhost_access(#user{username = _Username}, _VHost) ->
    true.

check_resource_access(#user{username = Username, impl = Token},
                      #resource{kind = Type, name = Name},
                      _Permission) ->
    SName = binary_to_list(Name),
    SUsername = binary_to_list(Username),
    SToken = binary_to_list(Token),
    case Type of
        exchange -> case SName of
                        "new"       -> true;
                        _           -> check_user_can_access_conversation_exchange(SUsername, SToken, SName)
                    end;
        queue    -> case string:substr(SName, 1, 7) of
                        "amq.gen"    -> true;
                        _            -> false
                    end
    end.

%%--------------------------------------------------------------------

oauth_check_token(OUsername, OToken) ->
    Params = [{scope,        "widgetcli"},
              {username,     OUsername},
              {access_token, OToken}],
    http_post(q(oauth_server, Params)).

check_user_can_access_conversation_exchange(UserName, OAuthToken, ExchangeName) ->
    RegExp = "^[a-f0-9]{24}$",
    case re:run(ExchangeName, RegExp) of
        nomatch            -> false;
        _                  -> max_get_conversation(UserName, OAuthToken, ExchangeName)
    end.

max_get_conversation(User, Token, ConversationID) ->
  {ok, MaxServerBase} = application:get_env(rabbitmq_auth_backend_max, max_server),
  ConversationsEndpoint = MaxServerBase ++ "/conversations/" ++ ConversationID,
  Headers = [
    {"X-Oauth-Scope", "widgetcli"},
    {"X-Oauth-Token", Token},
    {"X-Oauth-Username", User}],
  http_get(ConversationsEndpoint, Headers).

%%--------------------------------------------------------------------

http_get(Path, Headers) ->
    URI = uri_parser:parse(Path, [{port, 80}]),
    {host, Host} = lists:keyfind(host, 1, URI),
    {port, Port} = lists:keyfind(port, 1, URI),
    HostHdr = rabbit_misc:format("~s:~b", [Host, Port]),
    case httpc:request(get, {Path, Headers ++ [{"Host", HostHdr}]}, ?HTTPC_OPTS, []) of
        {ok, {{_HTTP, Code, _}, _Headers, _Body}} ->
            case Code of
                200 -> true;
                _   -> false
            end;
        {error, _} = E ->
            E
    end.

http_post(Path) ->
    ssl:start(),
    URI = uri_parser:parse(Path, [{port, 80}]),
    {host, Host} = lists:keyfind(host, 1, URI),
    {port, Port} = lists:keyfind(port, 1, URI),
    HostHdr = rabbit_misc:format("~s:~b", [Host, Port]),
    case httpc:request(post, {Path, [{"Host", HostHdr}], "application/text", "." }, ?HTTPC_OPTS, []) of
        {ok, {{_HTTP, Code, _}, _Headers, _Body}} ->
            case Code of
                200 -> true;
                _   -> false
            end;
        {error, _} = E ->
            E
    end.

q(PathName, Args) ->
    {ok, Path} = application:get_env(rabbitmq_auth_backend_max, PathName),
    R = Path ++ "?" ++ string:join([escape(K, V) || {K, V} <- Args], "&"),
    %%io:format("Q: ~p~n", [R]),
    R.

escape(K, V) ->
    atom_to_list(K) ++ "=" ++ mochiweb_util:quote_plus(V).

%%--------------------------------------------------------------------
