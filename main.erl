-module(main).
-behavior(gen_server).

-export([ hash_block/1
        , change_endianness/1
        , count_trailing_zeros/1
        , proof_of_work/1
        , validate_txn/2
        , init/1
        , start_link/0
        , handle_call/3
        , handle_cast/2
        , mine_block/2
        , create_txn/5
        , create_account/1
        ]).

-define(DIFFICULTY_TARGET, 5).
-define(REWARD_TOKENS, 10).

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

validate_txn(ChainStateTree, #txn{from = From, to = To, amount = Amount, sig = Sig}) ->
    AmountBin = <<Amount:32>>,
    Data = <<From/binary, To/binary, AmountBin/binary>>,
    ValidSig = crypto:verify(ecdsa, sha256, Data, Sig, [From, secp256k1]),

    FromBalance = binary:decode_unsigned(gb_merkle_trees:lookup(From, ChainStateTree)),
    ValidAmount = FromBalance >= Amount,

    ValidSig and ValidAmount.

start_link() ->
    gen_server:start_link({local, main}, main, [], []).

init(_Args) ->
    Header = #header{ prev_block_hash       = <<0>>
                    , difficulty_target     = ?DIFFICULTY_TARGET
                    , nonce                 = 0
                    , chain_state_root_hash = <<0>>
                    , txns_root_hash        = <<0>>
                    },
    GenesisBlock = #block{header = Header, txns = []},
    BlockChain = [GenesisBlock],
    TxnPool = [],
    ChainStateTree = gb_merkle_trees:empty(),
    {ok, {BlockChain, TxnPool, ChainStateTree}}.

handle_call({new_account, PubKey, PrivKey}, _From, {BlockChain, TxnPool, ChainStateTree}) ->
    NewTree = gb_merkle_trees:enter(PubKey, binary:encode_unsigned(0), ChainStateTree),
    {reply, {PubKey, PrivKey}, {BlockChain, TxnPool, NewTree}};
handle_call({new_txn, Txn}, _From, {BlockChain, TxnPool, ChainStateTree}) ->
    {reply, length(TxnPool), {BlockChain, TxnPool ++ [Txn], ChainStateTree}};
handle_call({mine_block, PubKey}, _From, {BlockChain, TxnPool, ChainStateTree}) ->
    P = fun(Tree, Txn) -> gb_merkle_trees:enter(Txn#txn.sig, binary:encode_unsigned(Txn#txn.amount), Tree) end,
    TxnsTree = lists:foldl(P, gb_merkle_trees:empty(), TxnPool),
    Header = #header{ prev_block_hash       = hash_block(lists:last(BlockChain))
                    , difficulty_target     = ?DIFFICULTY_TARGET
                    , nonce                 = 0
                    , chain_state_root_hash = gb_merkle_trees:root_hash(ChainStateTree)
                    , txns_root_hash        = gb_merkle_trees:root_hash(TxnsTree)
                    },
    RewardTxn = #txn{from = undefined, to = PubKey, amount = ?REWARD_TOKENS, sig = undefined},
    NewTxns = TxnPool ++ [RewardTxn],
    AllTxnsValid = lists:all(validate_txn, NewTxns),
    if
        AllTxnsValid ->
            NewBlock = proof_of_work(#block{header = Header, txns = NewTxns}),
            F = fun(Tree, #txn{from = From, to = To, amount = Amount}) ->
                    OldFromBalance = binary:decode_unsigned(gb_merkle_trees:lookup(From, Tree)),
                    OldToBalance = binary:decode_unsigned(gb_merkle_trees:lookup(To, Tree)),

                    NewFromBalance = binary:encode_unsigned(OldFromBalance - Amount),
                    NewToBalance = binary:encode_unsigned(OldToBalance + Amount),

                    T = gb_merkle_trees:enter(From, NewFromBalance, Tree),
                    gb_merkle_trees:enter(To, NewToBalance, T)
                end,
            NewChainStateTree = lists:foldl(F, ChainStateTree, NewTxns),
            {reply, NewBlock, {BlockChain ++ [NewBlock], [], NewChainStateTree}};
        true ->
            {noreply, {BlockChain, TxnPool, ChainStateTree}}
    end;
handle_call(_, _From, State) ->
    {stop, "Unrecognized call args", State}.

handle_cast({}, {BlockChain, TxnPool, ChainStateTree}) ->
    {noreply, {BlockChain, TxnPool, ChainStateTree}}.

mine_block(Pid, PubKey) ->
    gen_server:call(Pid, {mine_block, PubKey}).

create_txn(Pid, From, To, Amount, Priv) ->
    gen_server:call(Pid, {new_txn, create_txn(From, To, Amount, Priv)}).

create_txn(From, To, Amount, Priv) ->
    AmountBin = <<Amount:32>>,
    Data = <<From/binary, To/binary, AmountBin/binary>>,
    Sig = crypto:sign(ecdsa, sha256, Data, [Priv, secp256k1]),
    #txn{from = From, to = To, amount = Amount, sig = Sig}.

create_account(Pid) ->
    {PubKey, PrivKey} = crypto:generate_key(ecdh, secp256k1),
    gen_server:call(Pid, {new_account, PubKey, PrivKey}).
