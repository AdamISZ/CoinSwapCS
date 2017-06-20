#!/bin/bash

mk_bitcoinconf()
{
    cp ./regtest_bitcoin.conf ${tmpdir}/bitcoin.conf
    if [[ $? != 0 ]]; then
        echo "regtest_bitcoin.conf not found. re-run this script from the ./test directory" 2>&1
        exit 1
    fi
}

mk_coinswapconf()
{
    cp ./regtest_coinswapcs.cfg ${tmpdir}/coinswapcs.cfg
    if [[ ! -d $HOME/.CoinSwapCS ]]; then
        mkdir $HOME/.CoinSwapCS
    fi
}

clean_datadir()
{
    if [[ "$1" =~ /dev/shm/cstest[0-9]* ]]; then
        rm --preserve-root -rf "$1"
    else
        echo "not a temporary test directory : ${1}" 1>&2
    fi

    if [[ -d $1 ]]; then
        echo "directory not removed : ${1}" 1>&2
    fi
}

run_test()
{
    local test_result;
    py.test --btcroot="${bitcoind_dir}" --btcpwd=123456abcdef --btcconf="$1" --runtype="$2" -s | tee ${curtest}/pytest.log
    test_result="${PIPESTATUS[0]}"
    echo "${test_result}"
    if (( ${test_result} != 0 )) && [[ ${run_no_args} == true ]]; then
        exit 1
    fi
}

test_case()
{
    case "$@" in
        "")
            exit_on_fail="true"
            echo "${tests[@]} ${recovery_tests[@]}"
            ;;
        all)
            echo "${tests[@]} ${recovery_tests[@]}"
            ;;
        recovery)
            echo "${recovery_tests[@]}"
            ;;
        *)
            echo "$@"
            ;;
    esac
}

get_session_id()
{
    grep -o 'session_id": ".*",' ${curtest}/pytest.log | cut -d'"' -f3
}

mv_session_files()
{
    local session_id="$( get_session_id )"
    local alice_session="${session_dir}/alicestate${session_id}.json"
    local carol_session="${session_dir}/carolstate${session_id}.json"

    if [[ -r ${alice_session} ]]; then
        mv "${alice_session}" ${curtest}/
    fi

    if [[ -r ${carol_session} ]]; then
        mv "${carol_session}" ${curtest}/
    fi
}

main()
{
    local tests=( "cooperative" "badhandshake" "fakesecret" \
        "badhandshake" "badncs" "badcompleten" "badsendtx0id" "badreceivetx1id" \
        "badsendtx3sig" "nobroadcasttx0" "notx01monitor" "badreceivetx5sig" \
        "cbadhandshake" "cbadnegotiate" "cbadsendtx1id" "cbadreceivetx3sig" \
        "cnobroadcasttx1" "cbadreceivesecret" "cbadsendtx5sig" "cbadreceivetx4sig")
    local recovery_tests=( rc{3..9} ra{3..11} )

    local bitcoind_="${1:-$(which bitcoind)}" exit_on_fail="false"
    echo "using bitcoind : ${bitcoind_}" 2>&1
    if [[ ! -x ${bitcoind_} ]]; then
        echo "bitcoind not found or not executable : ${bitcoind_}" 1>&2
        return 1
    else
        local bitcoind_dir="$(dirname ${bitcoind_})/"
        shift
    fi

    local tmpdir="/dev/shm/cstest${RANDOM}"
    mkdir ${tmpdir}
    if [[ ! -d ${tmpdir} ]]; then
        echo "tmpdir not found or /tmp not writable : ${tmpdir}" 1>&2
        return 1
    fi
    if [[ "$1" == --keep ]]; then
        local keep=1
        shift
    fi

    local session_dir="$HOME/.CoinSwapCS/sessions"

    mk_bitcoinconf "${tmpdir}"
    mk_coinswapconf "${tmpdir}"
    local test_queue=( $( test_case "$@") )
    for test_case in ${test_queue[@]}; do
        curtest="${tmpdir}/${test_case}_${RANDOM}"
        mkdir ${curtest}
        cp ${tmpdir}/bitcoin.conf ${curtest}/bitcoin.conf
        echo "datadir=${curtest}" >> ${curtest}/bitcoin.conf
        ln -fs ${tmpdir}/coinswapcs.cfg $HOME/.CoinSwapCS/coinswapcs.cfg
        echo "testing : ${curtest}" 1>&2
        run_test "${curtest}/bitcoin.conf" "${test_case}"
        mv_session_files
        sleep 2
        if [[ -e ${curtest}/bitcoind.pid ]]; then
            mapfile btcpid <${curtest}/bitcoind.pid
            kill -9 ${btcpid}
            echo "bitcoind stalled and killed. pid : ${btcpid}" 1>&2
            sleep 1
        fi
    done

    if (( ${keep:-0} == 0 )); then
        clean_datadir "${tmpdir}"
    fi
    unlink $HOME/.CoinSwapCS/coinswapcs.cfg
}

main $@
