
:- set_prolog_flag(stack_limit, 8_147_483_648).

:- initialization((
    % set project-specific global flags
    set_logtalk_flag(report, warnings),
    set_logtalk_flag(events, allow),
    set_logtalk_flag(debug, on),
    logtalk_load(tutor(loader)),
    logtalk_load(tools(loader)),  % debugging, tracing, trace
    logtalk_load(debugger(loader)),  % debugging

    % load the project source files
    logtalk_load([pkt,'pkt_run']),
    debugger::debug,
    pkt_run::run,
    true
)).
