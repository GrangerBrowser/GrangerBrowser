from __future__ import annotations

import random
import time
import unittest

from granger_network.cells import CELL_SIZE, decode_cell
from granger_network.errors import GrangerNetworkError, ProtocolError
from granger_network.peer_rpc import MAX_RPC_PAYLOAD, RPC_HEADER, decode_rpc_frame
from granger_network.wan_application import (
    MAX_APPLICATION_MESSAGE,
    decode_application_request,
    decode_application_response,
)
from granger_network.wan_control import (
    RendezvousJoin,
    RendezvousRegistration,
    decode_intro_registration,
    decode_intro_request,
)
from granger_network.wan_discovery import (
    decode_find_node,
    decode_find_record,
    decode_node_list,
    decode_optional_record,
    decode_record_envelope,
)


class WanParserFuzzTests(unittest.TestCase):
    def test_random_bounded_inputs_are_accepted_or_rejected_by_protocol_errors(self) -> None:
        random_source = random.Random(0x4752414E474552)
        parsers = (
            decode_rpc_frame,
            decode_cell,
            decode_application_request,
            decode_application_response,
            decode_intro_registration,
            decode_intro_request,
            RendezvousRegistration.decode,
            RendezvousJoin.decode,
            decode_find_node,
            decode_find_record,
            decode_node_list,
            decode_optional_record,
            decode_record_envelope,
        )
        sizes = (0, 1, 2, 4, 8, 16, 31, 32, 63, 64, 127, 255, 511, 1023, 2048)
        started = time.monotonic()
        cases = 0
        for index in range(600):
            size = sizes[index % len(sizes)]
            if index % 7 == 0:
                size = CELL_SIZE
            content = random_source.randbytes(size)
            for parser in parsers:
                cases += 1
                try:
                    parser(content)
                except GrangerNetworkError:
                    pass
        self.assertEqual(cases, 7800)
        self.assertLess(time.monotonic() - started, 10.0)

    def test_declared_oversize_inputs_fail_before_payload_processing(self) -> None:
        with self.assertRaises(ProtocolError):
            decode_rpc_frame(b"\x00" * (RPC_HEADER.size + MAX_RPC_PAYLOAD + 1))
        with self.assertRaises(ProtocolError):
            decode_application_request(b"\x00" * (MAX_APPLICATION_MESSAGE + 1))
        with self.assertRaises(ProtocolError):
            decode_application_response(b"\x00" * (MAX_APPLICATION_MESSAGE + 1))
        with self.assertRaises(ProtocolError):
            decode_node_list(b"\xff\xff")
        with self.assertRaises(ProtocolError):
            decode_record_envelope(b"\x00\x20" + b"x" * 31)


if __name__ == "__main__":
    unittest.main()
