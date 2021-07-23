% Compile
c(main).

% Start the server
{ok, Pid} = main:start_link().

% Create the first account
{PubKey1, PrivKey1} = main:create_account(Pid).

% Create the second account
{PubKey2, PrivKey2} = main:create_account(Pid).

% Mine block for the first account
main:mine_block(Pid, PubKey1).

% Get the balance of the first account
main:get_balance(Pid, PubKey1).

% Transfer 3 tokens from the first to the second account
main:create_txn(Pid, PubKey1, PubKey2, 3, PrivKey1).

% Mine a block for the first account
main:mine_block(Pid, PubKey1).

% Get the balance of the first account
main:get_balance(Pid, PubKey1).
