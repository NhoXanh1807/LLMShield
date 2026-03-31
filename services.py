
import requests
import time
from classes import PromptRequest


def fetchPromptQueue() -> PromptRequest | None:
    try:
        res = requests.get("http://api.akng.io.vn:89/generation")
        if (res.status_code == 200 
            and "data" in res.json() 
            and res.json()["data"] is not None 
            and "id" in res.json()["data"] 
            and "prompt" in res.json()["data"]
        ):
            return PromptRequest(**res.json()["data"])
        else:
            return None
    except Exception as e:
        print(f"Error fetching prompt: {e}")
        time.sleep(5)
        print("Retrying fetch...")
        return None

def updateAnswer(id, answer) -> bool:
    try:
        res = requests.put("http://api.akng.io.vn:89/generation", json={
            "id": id,
            "answer": answer
        })
        if res.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error updating answer: {e}")
        time.sleep(5)
        print("Retrying update...")
        return False