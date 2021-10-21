:- use_module(library(option),[option/2]).
:- use_module(library(pprint),[print_term/2]).

:- object(pkt_run).
  :- use_module(library(option), [option/2]).
  :- use_module(library(pprint), [print_term/2]).

  :- public(run/0).
  run:-
    analyze.
    % test_split.

  load_all_tcp_icmp:-
    pcap('ih-tmp/very-total.pcap','tcp or icmp')::load.

  load_non_zero_length:-
    pcap('ih-tmp/very-total.pcap','tcp.len>0 or icmp')::load.

  connect_sniffer(Snif) :-
    % pcap_config::current_option(db_name,DBFile),
    pcap_config::current_option(test_db_name,DBFile),
    Snif=db(DBFile),
    Snif::connect_db.

  get_one:-
    % pcap_config::current_option(db_name,DBFile),
    connect_sniffer(Snif),
%    O::current_pack(Pkg),
%    O::layers(Pkg,Layers),!,
    Snif::current_pack(json(Layers)),!,
    print_term(Layers,[]),
    % packet(Layers)::field('eth.addr.oui_resolved'=Value),
    % debugger::trace,
    % packet(Layers)::tcp_flag(syn,N),
    % format('tcp_flag_syn:~w~n',[N]),
    P = packet(Layers),
    P::tcp_seq(N),
    format('~ntcp_seq:~w~n',[N]),
    \+ P::tcp_flag(fin),
    format('~n ! fin~n'),
    P::tcp_addr(src-dst, SD),
    format('tcp_src->dst:~w~n',[SD]),
    % TODO: Principle changed ..... the following code is not valid
    C = sate(Snif),
    C::conn_none((_:1024)-_, ConnNone),
%    C::conn_none(('192.168.1.10':1025)-('192.168.1.12':10000), ConnNone),
%    C::conn_none(('192.168.1.10':1024)-('192.168.1.11':10000), ConnNone),
    C::shift(ConnNone, ConnStartNone),!,
    format('conn_n_n:~w~n',[ConnStartNone]),
    C::shift(ConnStartNone,ConnStartStart),!,
    format('conn_s_s:~w~n',[ConnStartStart]),
    C::shift(ConnStartStart,ConnEstEst),!,
    format('conn_e_e:~w~n',[ConnEstEst]),
    C::shift(ConnEstEst,ConnEstEst1),!,
    format('conn_e_e1:~w~n',[ConnEstEst1]),
    C::shift(ConnEstEst1,ConnEstEst2),!,
    format('conn_e_e2:~w~n',[ConnEstEst2]),
    C::shift(ConnEstEst2,ConnEstEst3),!,
    format('conn_e_e3:~w~n',[ConnEstEst3]),
    true.

  analyze:-
    pcap_config::current_option(event_store_name, FileName),
    connect_sniffer(Snif),
    Saver = event_saver(FileName),
    Saver::connect,
    analyzer(Snif, Saver)::run(LastState),
    Saver::disconnect,
    format('LastState:~w~n',[LastState]).

  test_split:-
    Atom='ip.src.addr',
    packet(none)::split_ref(Atom,Head,Tail),
    format('Split:~w ~w ~n',[Head,Tail]).

:- end_object.
