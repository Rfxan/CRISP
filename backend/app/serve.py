"""Start the container API on the port supplied by the hosting platform."""
import os
import uvicorn


def main():
    try:
        port = int(os.getenv("PORT", "8000"))
    except ValueError:
        raise ValueError("PORT must be an integer between 1 and 65535") from None
    if not 1 <= port <= 65535:
        raise ValueError("PORT must be an integer between 1 and 65535")
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
