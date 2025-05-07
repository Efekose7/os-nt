
from flask import Flask, render_template, request
from osint_module import OsintTool
import io
import sys

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    if request.method == "POST":
        tool = OsintTool()
        target = request.form.get("target")
        mode = request.form.get("mode")

        sys.stdout = io.StringIO()  # Print çıktısını yakalamak için
        if mode == "domain":
            tool.domain_info(target)
        elif mode == "email":
            tool.email_lookup(target)
        elif mode == "username":
            tool.social_media_search(target)
        elif mode == "subdomain":
            tool.subdomain_scan(target)
        elif mode == "all":
            tool.domain_info(target)
            tool.subdomain_scan(target)

        output = sys.stdout.getvalue()
        sys.stdout = sys.__stdout__

    return render_template("index.html", output=output)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
