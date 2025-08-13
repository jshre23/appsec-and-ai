# How to Install requests for Jython (Burp Suite)

1. Download the following packages from https://pypi.org:
   - requests
   - urllib3
   - chardet
   - idna
   - certifi

   Download the `.zip` or `.tar.gz` source files (not `.whl`).

2. Extract each archive. Inside each, you will find a folder (e.g., `requests`, `urllib3`, etc.).

3. Locate your Jython installation directory. For Burp Suite, this is the Jython standalone JAR you configured in Extender > Options. If you do not have a `Lib/site-packages` folder, create it next to your Jython JAR.

4. Copy the extracted folders (`requests`, `urllib3`, `chardet`, `idna`, `certifi`) into the `Lib/site-packages` directory.

   Example structure:
   ```
   jython-standalone-2.7.3.jar
   Lib/
     site-packages/
       requests/
       urllib3/
       chardet/
       idna/
       certifi/
   ```

5. Restart Burp Suite and reload your extension.

6. Test by making a request in Burp. You should see ML prediction output in the Extender tab, and predictions should appear in your dashboard UI and logs.

---

If you encounter any errors, let me know the error message and I will help you resolve it.
