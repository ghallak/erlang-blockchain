-module(main).
-behavior(gen_server).

-export([ hash_block/1
        , some_block/0
        , change_endianness/1
        , count_trailing_zeros/1
        , proof_of_work/1
        , priv_key_1/0
        , priv_key_2/0
        , priv_to_pub/1
        , validate_txn/1
        , init/1
        , start_link/0
        , handle_call/3
        , handle_cast/2
        , mine_block/1
        , create_txn/5
        , create_dummy_txn/1
        ]).

-record(header, {prev_block_hash, difficulty_target, nonce, chain_state_root_hash, txns_root_hash}).

-type header() :: #header{ prev_block_hash       :: binary()
                         , difficulty_target     :: integer()
                         , nonce                 :: integer()
                         , chain_state_root_hash :: binary()
                         , txns_root_hash        :: binary() }.

-record(txn, {from, to, amount, sig}).

-type txn() :: #txn{ from   :: crypto:ecdh_public()
                   , to     :: crypto:ecdh_public()
                   , amount :: integer()
                   , sig    :: binary() }.

-record(block, {header :: header(), txns :: list(txn())}).

hash_block(#block{header = H}) ->
    PrevBlockHash = H#header.prev_block_hash,
    DifficultyTargetBin = H#header.difficulty_target,
    Nonce = H#header.nonce,
    ChainStateRootHash = H#header.chain_state_root_hash,
    TxnsRootHash = H#header.txns_root_hash,

    PrevBlockHash_ = change_endianness(PrevBlockHash),
    DifficultyTargetBin_ = <<DifficultyTargetBin:32/little>>,
    Nonce_ = <<Nonce:32/little>>,
    ChainStateRootHash_ = change_endianness(ChainStateRootHash),
    TxnsRootHash_ = change_endianness(TxnsRootHash),

    BlockBin = <<PrevBlockHash_/binary, DifficultyTargetBin_/binary, Nonce_/binary, ChainStateRootHash_/binary, TxnsRootHash_/binary>>,

    crypto:hash(sha256, crypto:hash(sha256, BlockBin)).

some_header() ->
    #header{ prev_block_hash = <<1>>
           , difficulty_target = 2
           , nonce = 0
           , chain_state_root_hash = <<2>>
           , txns_root_hash = <<3>> }.

some_txns() ->
    [].

some_block() ->
    #block{ header = some_header()
          , txns = some_txns() }.

change_endianness(Bin) ->
    binary:list_to_bin(lists:reverse(binary:bin_to_list(Bin))).

count_trailing_zeros(<<>>) ->
    0;
count_trailing_zeros(<<H,T/binary>>) ->
    if
        H == 0 ->
            8 + count_trailing_zeros(<<T/binary>>);
        H band 1 == 0 ->
            NH = H bsr 1,
            1 + count_trailing_zeros(<<NH, T/binary>>);
        true ->
            0
    end.

proof_of_work(Block) ->
    Header = Block#block.header,
    Nonce = Header#header.nonce,
    Target = Header#header.difficulty_target,

    Zeros = count_trailing_zeros(hash_block(Block)),

    if
        Zeros < Target ->
            proof_of_work(Block#block{header = Header#header{nonce = Nonce + 1}});
        true ->
            Block
    end.

priv_key_1() ->
    <<214,165,153,172,61,81,127,24,68,242,51,221,134,181,241,69>>.

priv_key_2() ->
    <<10,132,120,162,124,208,1,170,234,132,59,74,246,15,71,233>>.

priv_to_pub(Priv) ->
    element(1, crypto:generate_key(ecdh, secp256k1, Priv)).

validate_txn(#txn{from = From, to = To, amount = Amount, sig = Sig}) ->
    AmountBin = <<Amount:32>>,
    Data = <<From/binary, To/binary, AmountBin/binary>>,
    crypto:verify(ecdsa, sha256, Data, Sig, [priv_to_pub(priv_key_1()), secp256k1]).

start_link() ->
    gen_server:start_link({local, main}, main, [], []).

init(_Args) ->
    BlockChain = [],
    TxnPool = [],
    {ok, {BlockChain, TxnPool}}.

handle_call({add_txn, Txn}, _From, {BlockChain, TxnPool}) ->
    {reply, length(TxnPool), {BlockChain, TxnPool ++ [Txn]}};
handle_call(_, _From, State) ->
    {stop, "Unrecognized call args", State}.

handle_cast({}, {BlockChain, TxnPool}) ->
    {noreply, {BlockChain, TxnPool}}.

mine_block(Pid) ->
    gen_server:cast(Pid, {}).

create_txn(Pid, From, To, Amount, Priv) ->
    gen_server:call(Pid, {add_txn, create_txn(From, To, Amount, Priv)}).

create_txn(From, To, Amount, Priv) ->
    AmountBin = <<Amount:32>>,
    Data = <<From/binary, To/binary, AmountBin/binary>>,
    Sig = crypto:sign(ecdsa, sha256, Data, [Priv, secp256k1]),
    #txn{from = From, to = To, amount = Amount, sig = Sig}.

create_dummy_txn(Pid) ->
    From = priv_to_pub(priv_key_1()),
    To = priv_to_pub(priv_key_2()),
    Amount = 50,
    Priv = priv_key_1(),

    create_txn(Pid, From, To, Amount, Priv).
