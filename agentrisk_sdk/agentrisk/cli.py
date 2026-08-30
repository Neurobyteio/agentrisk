"""Command-line interface for AgentRisk."""

import argparse
import asyncio
import os
import sys

from agentrisk import AgentRisk


def main():
    parser = argparse.ArgumentParser(prog="agentriskm2m", description="Check a Base token for scam risk")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="Check a token address")
    check_parser.add_argument("token_address", help="Base token contract address (0x...)")

    args = parser.parse_args()

    private_key = os.environ.get("AGENTRISK_PRIVATE_KEY")
    if not private_key:
        print("Error: set AGENTRISK_PRIVATE_KEY environment variable with your Base wallet private key.")
        sys.exit(1)

    if args.command == "check":
        risk = AgentRisk(private_key=private_key)
        result = asyncio.run(risk.scan(args.token_address))
        print(f"Risk score: {result['risk_score']} / {result['risk_level']}")
        print(f"Verdict: {result['verdict']}")


if __name__ == "__main__":
    main()