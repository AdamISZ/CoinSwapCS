x=( rc{3..9} );
for thing in ${x[@]}; do
    py.test --btcroot=$1 --btcpwd=123456abcdef --btcconf=$2 --runtype="${thing}"
    [[ $? != 0 ]] && break && echo 1
    rm -rf ~/.bitcoin/regtest
    sleep 2
done

x=( ra{3..11} );
for thing in ${x[@]}; do
    py.test --btcroot=$1 --btcpwd=123456abcdef --btcconf=$2 --runtype="${thing}"
    [[ $? != 0 ]] && break && echo 1
    rm -rf ~/.bitcoin/regtest
    sleep 2
done && echo 0





