import os
from flask import Flask, render_template, request

from run_investigation import investigate_message


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    result = None
    message = ""
    error = None

    if request.method == "POST":

        message = request.form.get("message", "").strip()

        if not message:
            error = "Please enter a message to analyze."

        else:
            try:
                result = investigate_message(message)

            except Exception as e:
                error = f"Investigation failed: {str(e)}"

    return render_template(
        "index.html",
        result=result,
        message=message,
        error=error
    )


if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )