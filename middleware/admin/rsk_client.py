import os
import requests
import json


class RskClientError(RuntimeError):
    pass


class RskClient:
    def __init__(self, url):
        self._url = url

    @property
    def url(self):
        return self._url

    def get_best_block_number(self):
        try:
            return int(self._request("eth_blockNumber", []), 16)
        except Exception as e:
            raise RskClientError(f"While getting the best block number: {str(e)}")

    def get_block_by_number(self, number):
        try:
            return self._request("eth_getBlockByNumber", [hex(number), False])
        except Exception as e:
            raise RskClientError(f"While getting the block by number: {str(e)}")

    def _request(self, method, params):
        try:
            request_id = int.from_bytes(os.urandom(2), byteorder="big", signed=False)
            response = requests.post(
                self.url,
                headers={"content-type": "application/json"},
                data=json.dumps({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }),
            )

            if response.status_code != 200:
                raise ValueError(f"Got {response.status_code} response from the server")

            result = json.loads(response.text)

            if result["id"] != request_id:
                raise ValueError(
                    f"Unexpected response id {result['id']} (expecting {request_id})")

            return result["result"]
        except Exception as e:
            raise RskClientError(f"While calling the '{method}' method: {str(e)}")
