x=( "cooperative" "badhandshake" "fakesecret" \
"badhandshake" "badncs" "badcompleten" "badsendtx0id" "badreceivetx1id" \
"badsendtx3sig" "nobroadcasttx0" "notx01monitor" "badreceivetx5sig" \
"cbadhandshake" "cbadnegotiate" "cbadsendtx1id" "cbadreceivetx3sig" \
"cnobroadcasttx1" "cbadreceivesecret" "cbadsendtx5sig" "cbadreceivetx4sig")
 
for thing in ${x[@]}; do
    py.test --btcroot=/home/adam/bitcoin/bitcoin-0.13.1/bin/ --btcpwd=123456abcdef \
    --btcconf=/home/adam/bitcoin.conf --runtype="${thing}"
    [[ $? != 0 ]] && break && echo 1
    rm -rf ~/.bitcoin/regtest
    sleep 2
done && echo 0

