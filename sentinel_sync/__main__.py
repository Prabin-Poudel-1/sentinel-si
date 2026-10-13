"""Explicit local pairing/maintenance; never reads or uploads the audit database."""
import argparse
import getpass
from . import SyncClient


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["pair", "flush", "rotate", "disconnect"])
    parser.add_argument("--origin", required=True)
    parser.add_argument("--queue", required=True, help="Dedicated metadata queue SQLite path, not the audit DB")
    parser.add_argument("--consent", action="store_true", help="Explicitly allow optional metadata sync")
    args = parser.parse_args()
    client = SyncClient(args.origin, args.queue, consent=args.consent)
    if args.command == "pair":
        client.pair(getpass.getpass("One-use pairing code: "))
        print("Device paired. No audit contents were uploaded.")
    elif args.command == "flush":
        print(f"Acknowledged metadata events: {client.flush()}")
    elif args.command == "rotate":
        client.rotate()
        print("Device credential rotated.")
    else:
        client.disconnect()
        print("Device disconnected; local credential and pending metadata removed.")


if __name__ == "__main__":
    main()
