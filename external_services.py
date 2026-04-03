
import requests
import time
from interfaces import Request


def fetchRequest() -> Request | None:
    try:
        res = requests.get("http://api.akng.io.vn:89/llm")
        if (res.status_code == 200 
            and "data" in res.json() 
            and res.json()["data"] is not None 
            and "id" in res.json()["data"]
        ):
            return Request(
                id=res.json()["data"]["id"],
                action=res.json()["data"]["action"],
                data=res.json()["data"]["data"]
            )
        else:
            return None
    except Exception as e:
        print(f"Error fetching request: {e}")
        time.sleep(5)
        print("Retrying fetch...")
        return None

def updateResponse(id, response) -> bool:
    try:
        res = requests.put("http://api.akng.io.vn:89/llm", json={
            "id": id,
            "response": response
        })
        if res.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error updating response: {e}")
        time.sleep(5)
        print("Retrying update...")
        return False