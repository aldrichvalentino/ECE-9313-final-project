#!/usr/bin/env python3

# Run iperf TCP client until for requested duration

import os
import sys
import multiprocessing
import numpy as np

clients = {
    "10.0.0.101": ["10.0.0.102", "10.0.0.103", "10.0.0.104"],
    "10.0.0.102": ["10.0.0.101", "10.0.0.103", "10.0.0.104"],
    "10.0.0.103": ["10.0.0.101", "10.0.0.102", "10.0.0.104"],
    "10.0.0.104": ["10.0.0.101", "10.0.0.102", "10.0.0.103"],
}

ping_multipliers = 1.5
num_clients = 1

# seed numpy
np.random.seed(0)


def get_tos_label(flow_duration):
    if flow_duration >= -3:
        return 0xB8
    else:
        return 0x04


if __name__ == "__main__":
    # Check arguments
    if len(sys.argv) != 3:
        print("Usage: python client.py <duration> <current_server_ip>")
        sys.exit(1)

    duration = int(sys.argv[1])
    current_server_ip = sys.argv[2]

    # RNG for flow duration
    rng = np.random.default_rng()

    # Generate TCP iperf traffic
    for i in range(duration):
        commands = []
        for client_ip in clients[current_server_ip]:
            flow_duration = -1 * rng.integers(low=1, high=6)
            tos_label = get_tos_label(flow_duration)
            n_bytes = "1M" if flow_duration >= -3 else "64K"

            commands.append(
                f"iperf -c {client_ip} -p 80 -t 10e{flow_duration} -P {num_clients} -n {n_bytes} -S {tos_label}"
            )

        # Run iperf commands in parallel
        with multiprocessing.Pool() as pool:
            pool.map(os.system, commands)
