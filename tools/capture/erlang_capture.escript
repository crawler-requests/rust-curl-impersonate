#!/usr/bin/env escript
%% Capture the Erlang/OTP ssl client fingerprint through inets' httpc.
%% httpc speaks HTTP/1.1 only, so the record is written as an HTTP/1.1 client.
main([Out]) ->
    inets:start(),
    ssl:start(),
    Options = [
        {ssl, [{verify, verify_peer}, {cacerts, public_key:cacerts_get()}]},
        {timeout, 30000}
    ],
    {ok, {{_Version, 200, _Reason}, _Headers, Body}} =
        httpc:request(get, {"https://tls.peet.ws/api/all", []}, Options,
                      [{body_format, binary}]),
    ok = file:write_file(Out, Body),
    io:format(standard_error, "erlang ~s~n", [erlang:system_info(otp_release)]).
