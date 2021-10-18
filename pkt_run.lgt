:- use_module(library(option),[option/2]).

:- object(pkt_run).
  :- use_module(option, [option/2]).

  :- public(run/0).
  run:-
    get_one.
    % test_split.

  load_all_tcp_icmp:-
    pcap('ih-tmp/very-total.pcap','tcp or icmp')::load.

  load_non_zero_length:-
    pcap('ih-tmp/very-total.pcap','tcp.len>0 or icmp')::load.

  get_one:-
    pcap_config::current_option(test_db_name,DBFile),
    O=db(DBFile),
    O::connect_db,
%    O::current_pack(Pkg),
%    O::layers(Pkg,Layers),!,
    O::current_pack(json(Layers)),!,
    % packet(Layers)::field('eth.addr.oui_resolved'=Value),
    packet(Layers)::field('tcp.checksum'(Value)),
    % option(eth(Value),Layers),
    format('tcp.len:~w~n',[Value]).

  test_split:-
    Atom='ip.src.addr',
    packet(none)::split_ref(Atom,Head,Tail),
    format('Split:~w ~w ~n',[Head,Tail]).

:- end_object.
