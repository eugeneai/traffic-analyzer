:- use_module(library(process)).
:- use_module(library(sgml), [load_structure/3]).
:- use_module(util, [
     json_load/3,
     assert_package/1,
     retract_package/1,
     current_package/1,
     retractall_package/1,
     attach_package_db/1,
     detach_package_db
   ]).
:- use_module(library(option),[option/2,option/3]).
:- use_module(library(pcre),[re_replace/4]).

:- object(pcap_config).
  :- public([current_option/1, current_option/2]).
  current_option(A=B):-
    option(A,B).
  current_option(A,B):-
    option(A,B).

  % ek|fields|json|jsonraw|pdml|ps|psml|tabs|text
  option(output_format,'json').
  option(wireshark_executable, '/usr/bin/tshark').
  option(test_db_name, 'pcap-small.db').
  option(db_name, 'pcap.db').
  option(command_store_name, 'commands.pl').
  option(message_store_name, 'messages.pl').
  option(event_store_name, 'event.pl').
  % option()
:- end_object.

:- object(sniffing).
  :- public(current_pack/1).
  :- use_module(lists, [member/2]).
  :- use_module(library(option), [option/2,option/3]).
  :- public(layers/2).
  layers(json(Attrs), Layers):-
    option('_source'(json(Sources)),Attrs),
    option(layers(Layers),Sources).
:- end_object.

:- object(db(_FileName_),
     extends(sniffing)).

  :- use_module(util,[
       json_load/3,
       assert_package/1,
       retract_package/1,
       current_package/1,
       retractall_package/1,
       attach_package_db/1,
       detach_package_db/0
     ]).
  :- use_module(library(option), [option/2,option/3]).

  :- public(connect_db/0).
  connect_db:-
    attach_package_db(_FileName_).

  :- public(disconnect_db/0).
  disconnect_db:-
    detach_package_db.
  current_pack(Pkg):-
    current_package(Pkg).
%    current_package(Pkg),
%    retract_package(Pkg).

:- end_object.

:- object(pcap(_FileName_,_DisplayFilter_),
     extends(sniffing)).
  :- public(load/0).

  :- use_module(sgml,[load_structure/3]).
  :- use_module(process,[process_create/3]).
  :- meta_predicate(sgml:load_structure(*,*,*)).
  :- use_module(util,[
       json_load/3,
       assert_package/1,
       retract_package/1,
       current_package/1,
       retractall_package/1,
       attach_package_db/1,
       detach_package_db/0
     ]).
  :- use_module(lists,[member/2]).

  load :-
    pcap_config::current_option(wireshark_executable, Exec),
    pcap_config::current_option(output_format, Format),
    get_args(Format, Args),
    format('Exeuting ~w ~w ~n | swilgt ...',[Exec,Args]),
    process_create(Exec, Args, [stdout(pipe(Pipe))]),
    % load_structure(Pipe, Content, [dialect(xml)]),
    json_load(Pipe, Content, [null(null), true(true), flase(false)]),
    format('JSON loaded~nNow converting into db.',[]),
    % Content=[H|_],
    % format('\n~w~n',[H]),
    store(Content),
    true.

  get_args(Format, ['-r', _FileName_, '-T', Format]):-
    _DisplayFilter_ = none, !.
  get_args(Format, ['-r', _FileName_, '-Y', _DisplayFilter_, '-T', Format]).

  :- public(store/1).
  store(Packages):-
    pcap_config::current_option(db_name,DBFile),
    attach_package_db(DBFile),
    forall(member(P,Packages), package_store(P)),
    detach_package_db.

  package_store(JSON):-
    ::layers(JSON,Layers),
    assert_package(Layers).
%    format('STORING: ~w~n',[JSON]).

:- end_object.

:- object(analyzer(_Events_, _Receiver_)).
   :- use_module(library(pcre),[re_replace/4]).
   :- use_module(library(crypto),[hex_bytes/2]).
   :- use_module(lists,[append/3]).
   :- use_module(user,[open_codes_stream/2]).

   :- protected(current_event/2).
   current_event(Ev, PkgN) :-
     _Events_::current_term(event(PkgN, Ev)).
   :- protected(event/1).
   event(Ev):-
     _Receiver_::event(Ev).
   :- protected(event/2).
   event(Ev,Mark):-
     _Receiver_::event(Ev, Mark).

   :- public(run/0).
   run :-
      ::init,
      forall(
        current_event(Ev, PkgN),
        ::analyze(Ev, PkgN)).

   :- protected(analyze/2).
   % None here, Implemented by subclass
   analyze(_,_):-fail.

   :- protected(init/0).
   init. % Nothing to do by default.

   :- protected(buffer_bytes/2).
   buffer_bytes([], []).
   buffer_bytes([X|T], R) :-
     buffer_bytes(T, R1),
     buffer_bytes(X, BX),
     append(R1, BX, R).
   buffer_bytes(Buf, Bytes) :-
     re_replace(':'/g, '', Buf, Str),
     hex_bytes(Str, Bytes).

   :- protected(buffer_string/2).
   buffer_string(Buf, Str) :-
     buffer_bytes(Buf, Bytes),
     string_chars(Str,Bytes).

   :- protected(open_buffer/2).
   open_buffer(Buf, Stream) :-
     buffer_bytes(Buf, Bytes),
     open_codes_stream(Bytes, Stream).

   :- public(bytes_dump/1).
   bytes_dump(Bytes) :-
     open_codes_stream(Bytes, Stream),
     dump_lines(Stream, 0),
     close(Stream).

   dump_lines(Stream, N) :-
     % debugger::trace,
     read_string(Stream, 16, S16),
     S16\="",!,
     string_length(S16,L16),
     string_codes(S16, C16),
     hex_bytes(Bytes, C16),
     string_codes(Bytes, BB),
     thin(BB,BBS),
     string_codes(BBytes,BBS),
     % debugger::trace,
     clean_chars(C16,CC16),
     format('~16r_|_~w_|_~s_|~n',[N, BBytes, CC16]),
     L1 is N + L16,
     dump_lines(Stream, L1).
   dump_lines(_,_).

   thin([C1,C2],[C1,C2]) :- !.
   thin([C1,C2|T], [C1,C2,32|CT]) :-
     thin(T,CT).

   clean_char(C,C) :-
     C >= 32, C < 128,!.
   clean_char(_,46).

   clean_chars([],[]).
   clean_chars([C|T],[CC|R]) :-
     clean_char(C,CC),
     clean_chars(T,R).

   :- public(buffer_dump/1).
   buffer_dump(Buf) :-
     buffer_bytes(Buf, Bytes),
     bytes_dump(Bytes).
:- end_object.

:- object(packet(_Layers_)).
   :- use_module(library(option), [option/2]).
   :- use_module(lists, [member/2,append/3]).

   :- protected(path/2).
   :- dynamic(path/2).

   update_path(Option, SubPath) :-
     Option=..[Name,_],
     % debugger::trace,
     (
      path(Name, Path) ->
        P=Path ;
        P = []
     ),
     % format('~nUPDATE ~w as ~w adding ~w~n', [Name, P, SubPath]),
     (
       P = [SubPath|_] ->
        true ;
        retractall(path(Name, Path)),
        assertz(path(Name, [SubPath|P]))
     ).  % ! Reverse order

   :- public(print_paths/2).
   print_paths(Option, Path) :-
     forall(path(Option, Path), format('~w->~w~n',[Option, Path])).

   :- protected(field/3).
   field([],A,A).
   field([Subpath|T],A,Value):-
     field(T,A,Attrs),  % ! Reverse order
     Segment=..[Subpath, json(Value)],
     % ( Attrs==json(_)-> format('~nBAD TYPE Attrs 2~n');true ),
     option(Segment,Attrs).

   :- public(field/2).
   field(Option, json(Attrs)):-
     field(Option, Attrs),!.
   field(Option, Attrs):-
     Attrs\=json(_),
     option(Option, Attrs),!.

   field(Option, Attrs):-
     Option=..[Name,_],
     path(Name, Path),!,
     field(Path, Attrs, SubTree),
     % debugger::trace,
     field(Option, SubTree).
   field(Option, Attrs):-
     Attrs\=json(_),
     Option =.. [Name,_],
     split_ref(Name, Head, _),
     Op1 =.. [Head, json(JSON)],
     option(Op1, Attrs),
     % format('UPDATE REQ1'),
     update_path(Option,Head),
     field(Option, JSON),!.
   % field(Option, Attrs):-
   %   Attrs\=json(_),
   %   member(SubPath=json(A),Attrs),
   %   format('TRY ~k on ~w in ~w subtree ~n',[Option, A, SubPath]),
   %   field(Option, A),
   %   format('UPDATE REQ2'),
   %   update_path(Option, SubPath).

   :- public(field/1).
   field(Option):-
     field(Option, _Layers_).

   :- public(split_ref/3).
   split_ref(Atom,Ref,Refs):-
     atom(Atom),
     sub_atom(Atom,B,1,TL,'.'),
     S is B+1,
     sub_atom(Atom,S,TL,0,Refs),
     sub_atom(Atom,0,B ,_,Ref),!.

   :- public(tcp_addr/2).
   tcp_addr(src, A:P):-
     field('ip.src'(A)),
     field('tcp.srcport'(B)),
     atom_number(B,P).
   tcp_addr(dst, A:P):-
     field('ip.dst'(A)),
     field('tcp.dstport'(B)),
     atom_number(B,P).
   tcp_addr(src-dst,S-D):-
     tcp_addr(src,S),
     tcp_addr(dst,D).

   :- public(ip_addr/2).
   ip_addr(src,S) :-
     field('ip.src'(S)).
   ip_addr(dst,D) :-
     field('ip.dst'(D)).
   ip_addr(src-dst,S-D) :-
     ip_addr(src,S),
     ip_addr(dst,D).

   :- public(time/2).
   time(abs,A):-
     field('frame.time_epoch'(A)).

   :- public(eth_addr/2).
   eth_addr(src,A):-
     field('eth.src_tree'(json(Tree))),
     field('eth.addr'(A),Tree).
   eth_addr(dst,A):-
     field('eth.dst_tree'(json(Tree))),
     field('eth.addr'(A),Tree).

   :- public(number/1).
   number(N):-
     field('frame.number'(A)),!,
     atom_number(A,N).

   :- public(tcp_flag/2).
   tcp_flag(Flag,A):-
     member(Flag,[ns,cwr,ecn,urg,ack,push,reset,syn,fin]),
     field('tcp.flags_tree'(T)),
     atom_concat('tcp.flags.',Flag,F),
     Q =.. [F,A],
     field(Q,T).

   :- public(tcp_flag/1).
   tcp_flag(Flag):-
     tcp_flag(Flag,'1').

   :- public(tcp_fin/0).
   tcp_fin :-
     tcp_flag(fin).

   :- public(tcp_push/0).
   tcp_push :-
     tcp_flag(push).

   :- public(tcp_ack/1).
   tcp_ack(N):-
     tcp_flag(ack),
     field('tcp.ack_raw'(A)),
     atom_number(A,N).

   :- public(tcp_seq/1).
   tcp_seq(N):-
     tcp_flag(syn),
     field('tcp.seq_raw'(A)),
     atom_number(A,N).

   :- public(tcp_len/1).
   tcp_len(N):-
     field('tcp.len'(A)),
     atom_number(A,N).

   :- public(tcp_payload/1).
   tcp_payload(Data):-
     field('tcp.payload'(Data)).
:- end_object.

:- object(state(_Pkg_)).
   :- public(inc/2).
   inc(A,B):- add(A,1,B).
   :- public(add/3).
   add(A,B,C):-
     C is (A + B) mod 4294967296.

   :- protected(tcpep/2). % tcp end point
   %                state,     ip:port       syn:ack receive buffer
   tcpep(Ip:Port, e(none,      Ip:Port,     none:none,  []         )).

   :- public(conn_none/2).
   % TODO: sa(SYNS-ACKS,SYND-ACKD)
   %         Addrs  SRC  DST       sa    receiver buffers
   conn_none(S-D, c(SE,DE)) :-
     tcpep(S,SE),
     tcpep(D,DE).

   ack(A):-
     _Pkg_::tcp_ack(A),
     \+ _Pkg_::tcp_fin.
   conn_ack(A,A1):-
     inc(A,A1),
     _Pkg_::tcp_ack(A1),
     \+ _Pkg_::tcp_fin.
   fin_ack(A):-
     inc(A,A1),
     _Pkg_::tcp_ack(A1),
     _Pkg_::tcp_fin.

   :- protected(tcp_payload/4).
   tcp_payload(SS,SS1, DB,DB1) :-
     (
      _Pkg_::tcp_len(LA), LA>0 ->
        add(SS,LA,SS1),
        _Pkg_::tcp_payload(Data),
        DB1=[Data|DB] ;
        SS1 = SS,
        DB1 = DB
     ).

   :- public(shift/4).

   shift(   % ----> Syn
       tcp,
       c(e(none ,S,  _:SA, SB), e(none,D, DS:DA,DB)),
       c(e(start,S, SS:SA, SB), e(none,D, DS:DA,DB)),
       init
       ) :-
     _Pkg_::tcp_seq(SS),    % Generated
     \+ _Pkg_::tcp_fin,!.

   shift(   % ----> Ack
       tcp,
       c(e(none, S,  _:_,  SB), e(start,D, DS:DA ,DB)),
       c(e(start,S, SS:SA, SB), e(start,D, DS:DA,DB)),
       syn
   ) :-
     _Pkg_::tcp_seq(SS),  % Generated
     conn_ack(DS,SA),!.

   shift(   % ----> Ack
       tcp,
       c(e(start,S, SS :_,  SB), e(start,D, DS:DA, DB)),
       c(e(est  ,S, SS1:SA, SB), e(est  ,D, SA:DA, DB)),
       established
   ) :-
     inc(SS,SS1),
     conn_ack(DS,SA),!.

   % Pushing
   shift(   % ----> push
       tcp,
       c(e(est,S,  SS:SA, SB), e(est,D, DS:_,   DB)),
       c(e(est,S, SS1:SA, SB), e(est,D, DS:SS1, [])),
       push(DB1)
    ) :-
     _Pkg_::tcp_push,
     tcp_payload(SS,SS1, DB, DB1),
     ack(SA),!.

   shift(   % ----> ACK
       tcp,
       c(e(est,S,  SS:SA, SB), e(est,D, DS:_, DB)),
       c(e(est,S, SS1:SA, SB), e(est,D, DS:SS1, DB1)),
       ack
       ) :-
     _Pkg_::tcp_ack(GSA),
     GSA=<SA,             % Check and late ack
     \+ _Pkg_::tcp_fin,
     tcp_payload(SS,SS1, DB,DB1).

   shift(   % ----> ACK,Fin
       tcp,
       c(e(est,S, SS:SA, SB), e(est,D, DS:DA, DB)),
       c(e(fw1,S, SS:SA, SB), e(cw, D, DS:DA, DB)),
       fin_start
       ) :-
     _Pkg_::tcp_ack(SA),    % Check
     _Pkg_::tcp_fin,!.

   shift(   % ----> Ack (finalizing)
       tcp,
       c(e(cw, S, SS:SA, SB), e(fw1, D, DS:DA, DB)),
       c(e(cw, S, SS:SA, SB), e(fw1, D, DS:DA, DB)),
       fin_ack
       ) :-
     % format('~nPKG:~w~n ',[
     %   c(e(cw,S,  SS:SA, SB), e(fw1,D, DS:DA, DB))
     % ]),
     % debugger::trace,
     conn_ack(SA,_),!.

   shift(   % ----> Ack,Fin
       tcp,
       c(e(cw,  S, SS:SA, SB),   e(fw1,    D, DS:DA, DB)),
       c(e(last,S, SS:SA, SB), e(closed, D, DS:DA, DB)),
       fin_ack
       ) :-
     fin_ack(SA),!.

   shift(   % ----> Ack,FIN
       tcp,
       c(e(cw,    S, SS:SA, SB), e(fw2,    D, DS:DA, DB)),
       c(e(last  ,S, SS1:SA, SB), e(closed, D, DS:DA, [])),
       [push(DB1),fin_fin]
       ) :-
     fin_ack(SA),!,
     tcp_payload(SS,SS1, DB,DB1).

   shift(   % ----> ACK
       tcp,
       c(e(closed,S, SS:SA, SB), e(last,   D, DS:DA, DB)),
       c(e(closed,S, SS:SA, SB), e(closed, D, DS:DA, DB)),
       closed
       ) :-
     conn_ack(SA,_),!.

   % reset
   shift(   % ----> Rst
       tcp,
       c(e(none,  S,    _:_,  SB), e(start,  D, DS:DA, DB)),
       c(e(closed,S, none:SA, SB), e(closed, D, DS:DA, DB)),
       reset
   ) :-
     _Pkg_::tcp_flag(reset),
     conn_ack(DS,SA),!.

   % icmp
   shift(   % ---->
       ip,
       c(e(none, S, _,    SB),e(none,D, _,    DB)),
       c(e(none, S, none, SB),e(none,D, none, DB)),
       icmp
       ) :-
     % debugger::trace,
     _Pkg_::field('ip.proto'('1')).
:- end_object.

:- object(event_receiver).
   :- public(event/2).
   :- public(event/1).
:- end_object.

:- object(connections(_Pkg_)).
   :- public(shift/3).
   shift([], List, Event):-
     _Pkg_::number(N),
     % (N>=25000,!,
     % debugger::trace;true),
     state(_Pkg_)::conn_none(_-_,InitialState),!,
     shift(InitialState,NewState,Event),!,
     (
       final_state(Event) ->
         List = [];
         List = [s(NewState,[N])]
     ).

   % forward direction
   shift(State, NextState, e(Event,S-D)):-
     State=c(e(_,S,_,_),e(_,D,_,_)),
     _Pkg_::tcp_addr(src-dst,S-D),!,
     state(_Pkg_)::shift(tcp, State, NextState, Event),
     !.
   % in reverse direction
   shift(
     c(SE, DE), c(SE1,DE1), backward(e(Event,S-D))
   ):-
     c(SE, DE)=c(e(_,S,_,_),e(_,D,_,_)),
     _Pkg_::tcp_addr(src-dst,D-S),!,
     state(_Pkg_)::shift(
      tcp,
      c(DE, SE), c(DE1,SE1), Event
   ),!.
   % ICMP/IP
   shift(State, NextState, e(Event,S-D)):-
     State=c(e(none,S:_,_,_),e(none,D:_,_,_)),
     _Pkg_::ip_addr(src-dst,S-D),!,
     % format('~nicmp ~w~n',[S-D]),
     state(_Pkg_)::shift(ip, State, NextState, Event),
     !.
   shift([s(State,_)|T],NT, [removed(closed(S-D)),Event]) :-
     State=c(e(closed,S:_,_,_),e(closed,D:_,_,_)),!,
     shift(T,NT,Event).
   shift([s(State,_)|T],T, Event) :-
     shift(State, _, Event),
     final_state(Event),!.
   shift([s(State,P)|T],[s(NextState,N)|T], Event) :-
     shift(State, NextState, Event),
     _Pkg_::number(N),
     N>P, % Just for a case
     !.
   shift([X|T],[X|R],Event) :-
     shift(T, R, Event),!.
   :- protected(final_state/1).
   final_state(closed).
   final_state(reset).
   final_state(icmp).
   final_state(removed).
:- end_object.

:- object(frame_analyzer(_Sniffing_,_Receiver_)).
   :- protected(current_pack/1).
   current_pack(packet(Layers)) :-
     _Sniffing_::current_pack(json(Layers)).
   :- protected(init/1).
   init([]).
   :- protected(state/1).
   :- dynamic(state/1).
   :- public(run/1).
   run(LastState) :-
     init(State),
     assertz(state(State)),
     proceed(LastState).
   :- use_module(user,[gtrace/0]).
   :- use_module(lists,[member/2]).
   :- protected(proceed/1).
   proceed(LastState):-
     nl,
     forall(
       (
         current_pack(Pkg),
         % format('~nP ~n'),
         Pkg::number(PkgN),
         % PkgN>=25010,
         % PkgN<25000,
         format('PKG ~w~n',[PkgN]),
         true
       ),
       (
         state(State),
         % format('Current State ~w ~n',[State]),
         connections(Pkg)::shift(State,NextState,Event),
         format('Event ~w ~n',[Event]),!,
         _Receiver_::event(Event,PkgN),!,
         retract(state(State)),!,
         assertz(state(NextState)),
         % Pkg::print_paths(_,_)
         true
       )
     ),
     state(LastState),
     forall(member(X,LastState),
      _Receiver_::event(removed(state(X)),none)).
:- end_object.


:- object(message_analyzer(_Events_, _Receiver_),
     extends(analyzer(_Events_,_Receiver_))).

   :- dynamic(conn/2).
   :- private(conn/2).
   :- protected(current_conn/2).
   current_conn(Client,Server):-
     conn(Client,Server).

   init.

   to_107(_ , '192.168.1.107' : _).
   to_10(_ , '192.168.1.10' : N) :- N\=50000.

   from_1('192.168.1.1' : _, _).

   % from XEPR connect only to CTRL
   % CTRL to BR, command length either 8 bytes (00000) or 16

   to_11(_, '192.168.1.11':_).
   to_12(_, '192.168.1.12':_).
   to_ESIG(S,D) :-
     to_11(S,D).
   to_ESIG(S,D) :-
     to_12(S,D).

   to_TNK(_,'192.168.1.14':_).
   to_HALL(_,'192.168.1.13':_).
   to_SPJET(_,'192.168.1.16':_).
   to_PTJET(_,'192.168.1.16':_).

   ctrl_cmds('192.168.1.10':_,IP:_) :-
     IP\='192.168.1.1'.

   xchg(S,D):-
     from_1(S,D).
   xchg(S,D):-
     ctrl_cmds(S,D).

   filter(S,D) :-
     xchg(S,D).

   dns('00:50:c2:00:5a:b3', 'CNTRL', '192.168.1.10').
   dns('00:15:17:6a:98:1f', '_XEPR', '192.168.1.1').
   dns('00:00:ad:0e:93:12', 'ESIGL', '192.168.1.12').
   dns('00:00:ad:0e:91:12', 'ESIGH', '192.168.1.11').
   dns('00:00:ad:0b:75:12', 'TNKR0', '192.168.1.14').
   dns('00:00:ad:0e:e3:12', 'EHALL', '192.168.1.13').
   dns('00:30:64:05:af:8c', 'SPJET', '192.168.1.16'). % No DATA
   dns('00:00:ad:0d:86:12', 'ABRIG', '192.168.1.107').
   dns('00:00:ad:0b:74:12', 'PTJET', '192.168.1.15'). % No DATA

   dns(IP:Port, Name:Port) :-
     dns(_, Name, IP).

   analyze(e(push(Data), S-D), N) :-
     filter(S,D),
     !,
     % debugger::trace,
     dns(S,SN),
     dns(D,DN),
     format('~n~w REQ: from ~w to ~w~n', [N, SN,DN]),
     % buffer_dump(Data).
     ::buffer_bytes(Data, Bytes),
     ::event(e(command,S-D,Bytes), N).

   analyze(backward(e(push(Data), S-D)), N) :-
     filter(S,D),
     !,
     dns(S,SN),
     dns(D,DN),
     format('~n~w ANS: to ~w from ~w~n', [N, SN,DN]),
     % buffer_dump(Data).
     ::buffer_bytes(Data, Bytes),
     ::event(e(answer,S-D,Bytes), N).

   analyze(e(icmp, _-_), N) :- !,
     format('~n~w ICMP~n',[N]).

   analyze(_,_):-!.
   analyze(Event, PkgN) :-
     format('SKIP: ~w ~w ~n',[PkgN,Event]).

:- end_object.


:- object(command_analyzer(_Events_, _Receiver_),
      extends(analyzer(_Events_, _Receiver_))).

    init:-
      format('Initialization test~n').

    analyze(Ev, N):-
      format('Got event ~w at ~w~n',[Ev,N]).

:- end_object.
% Util objects ---- might be make them the same?

:- object(event_saver(_FileName_), extends(event_receiver)).
   :- protected(stream/1).
   :- dynamic(stream/1).
   :- public(connect/0).
   connect :-
     open(_FileName_, write, Stream),!,
     assertz(stream(Stream)),
     !.
   :- public(disconnect/0).
   disconnect :-
     retract(stream(Stream)),!,
     close(Stream),!.
   event([],_):-!.
   event([Event|T],N) :- !,
     event(Event,N),
     event(T,N).
   event(Event, N) :-
     stream(Stream), !,
     format(Stream, '~k.~n', [event(N,Event)]),!.

   % Event without mark note is none-marked event.
   event(Event):-
     event(Event, none).
:- end_object.

:- object(term_reader(_FileName_)).

   :- use_module(user, [setup_call_cleanup/3]).

   :- public(current_term/1).
   current_term(T):-
     setup_call_cleanup(open(_FileName_, read, Stream, []),
       current_term(Stream, T),
       close(Stream)).

   current_term(Stream, T) :-
     repeat,
     (read_term(Stream, T0, []),
      T0 \= end_of_file
      -> T=T0 ; !, fail).

:- end_object.
