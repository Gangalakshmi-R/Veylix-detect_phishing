from fastapi import FastAPI

from pydantic import BaseModel

from predict import (
    analyze_message_text
)


app = FastAPI(

    title=(
        "PhishIntel "
        "Phishing Investigation API"
    ),

    description=(
        "AI-assisted multi-channel "
        "phishing message investigation."
    ),

    version="1.0.0"
)


class AnalyzeRequest(
    BaseModel
):

    message: str


@app.get("/")
def root():

    return {

        "application":
            "PhishIntel",

        "description":
            (
                "Explainable phishing "
                "message investigation"
            ),

        "status":
            "running"
    }


@app.get("/health")
def health():

    return {

        "status":
            "healthy"
    }


@app.post(
    "/api/analyze"
)
def analyze(
    request: AnalyzeRequest
):

    return analyze_message_text(
        request.message
    )