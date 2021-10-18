:- module(util, [json_load/3, assert_package/1,
                 retract_package/1,
                 current_package/1,
                 retractall_package/1,
                 attach_package_db/1,
                 detach_package_db/0
                ]).

:- use_module(library(http/json),[json_read/3]).
:- use_module(library(persistency)).

:- persistent package(layers:acyclic).

attach_package_db(File):-
    db_attach(File, [sync(none)]).

detach_package_db:-
    db_sync(close),
    db_detach.

current_package(P):-
    package(P).

json_load(A,B,C):-
    json_read(A,B,C).
