-module(main).

-export([hash_block/1, some_block/0, change_endianness/1]).

-record(header, {prev_block_hash, difficulty_target, nonce, chain_state_root_hash, txns_root_hash}).

-type header() :: #header{ prev_block_hash       :: binary()
                         , difficulty_target     :: integer()
                         , nonce                 :: integer()
                         , chain_state_root_hash :: binary()
                         , txns_root_hash        :: binary() }.

-record(txn, {from, to, amount, sig}).

-type txn() :: #txn{ from   :: crypto:ecdh_public()
                   , to     :: crypto:ecdh_public()
                   , amount :: float()
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
           , difficulty_target = 1
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
