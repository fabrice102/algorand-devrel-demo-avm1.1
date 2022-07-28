import sys
import traceback
import base64

from Cryptodome.Hash import keccak
from algosdk.future.transaction import *

from .app import get_approval, get_clear
from ..utils import get_accounts, create_app, delete_app

client = algod.AlgodClient("a" * 64, "http://localhost:4001")


def call_application_keccak256(
        acct: tuple[any, str], app_id: int, message: bytes,
) -> bytes:
    """
    Call the application with message
    See comment of app.approval() to see what it does
    """
    addr, pk = acct

    sp = client.suggested_params()

    actxn = ApplicationCallTxn(
        addr,
        sp,
        app_id,
        OnComplete.NoOpOC,
        app_args=[message]
    )

    # Group and sign
    stxn = actxn.sign(pk)
    txid = stxn.transaction.get_txid()

    # Ship it
    client.send_transaction(stxn)

    # Get back the logs
    results = [wait_for_confirmation(client, txid, 4)]
    return get_logs_recursive(results)[0]


def test_application_eth_ecdsa_recover(
        acct: tuple[any, str], app_id: int, message: bytes,
):
    """
    Test the application app_id on a given message, signature, signer
    Check the logged value by the application matches the signer
    """
    returned_hash = call_application_keccak256(
        acct,
        app_id,
        message
    )

    m = keccak.new(digest_bits=256)
    m.update(message)
    expected_hash = m.digest()

    print("Message:                 {}".format(message))
    print("Hash expected in base64: {}".format(base64.b64encode(expected_hash)))
    print("Hash returned in base64: {}".format(base64.b64encode(returned_hash)))
    print("Hash expected in hex:    {}".format(expected_hash.hex()))
    print("Hash returned in hex:    {}".format(returned_hash.hex()))
    if expected_hash == returned_hash:  # need to lowercase to remove checksum
        print("  Success")
    else:
        print("  Fail")
    print()


def demo():
    # Create acct
    acct = get_accounts()[1]
    addr, pk = acct
    print("Using account {}".format(addr))

    # Read in the json contract description and create a Contract object
    try:
        # Create app
        app_id = create_app(
            client, addr, pk, get_approval=get_approval, get_clear=get_clear
        )
        app_addr = logic.get_application_address(app_id)
        print("Created App with id: {} and address {}".format(app_id, app_addr))

        # Pay the app address so we can execute calls
        sp = client.suggested_params()
        ptxn = PaymentTxn(addr, sp, app_addr, int(1e9))
        stxn = ptxn.sign(pk)
        client.send_transaction(stxn)

        # Normally here we'd like to wait for this transaciton to take place
        # However, in a sandbox environment, this is not necessary
        # so we cheat to go faster
        # In real life, uncomment the two lines below

        # txid = stxn.transaction.get_txid()
        # wait_for_confirmation(client, txid, 4)

        # Test on hashing of "hello"
        message = b"hello"
        test_application_eth_ecdsa_recover(acct, app_id, message)

    except:
        print("Fail :(\n", file=sys.stderr)
        traceback.print_exc()
    finally:
        print("Cleaning up")
        delete_app(client, app_id, addr, pk)


def get_logs_recursive(results: list[any]):
    logs = []
    for res in results:
        if "logs" in res:
            for l in [base64.b64decode(log) for log in res["logs"]]:
                logs.append(l)
        if "inner-txns" in res:
            logs.extend(get_logs_recursive(res["inner-txns"]))

    return logs


if __name__ == "__main__":
    demo()
