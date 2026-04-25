# SPDX-License-Identifier: MIT
import pickle
import subprocess


def handler(event, context):
    expression = event.get("expression", "1 + 1")
    command = event.get("command", "echo ok")
    payload = event.get("payload", b"")

    result = eval(expression)
    subprocess.run(command, shell=True, check=False)
    data = pickle.loads(payload)

    return {"result": result, "data": str(data)}
