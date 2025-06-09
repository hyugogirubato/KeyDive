# Challenge

To extract unencrypted challenges using KeyDive and HTTP Toolkit, you can follow this comprehensive guide. Assumes familiarity with both KeyDive and HTTP Toolkit, focusing on their integration for extracting unencrypted challenges effectively.

### Extract Unencrypted Challenges

#### 1. Prepare HTTP Toolkit

- Start [HTTP Toolkit](https://httptoolkit.com/) on your machine.
- Ensure it's configured to intercept HTTP and HTTPS traffic from your Android device. HTTP Toolkit provides detailed instructions on how to set this up based on your operating system.

#### 2. Set Up Environment

- Have an Android device with Widevine L3 DRM content that you want to analyze.
- Ensure the device is rooted or has adb access to interact with KeyDive and HTTP Toolkit effectively.

#### 3. Configure KeyDive

- Ensure KeyDive is set up to run on your Android device. This involves:
    - Installing KeyDive on your device via Magisk or another suitable method.
    - Running KeyDive with the necessary configurations to intercept DRM-related requests.

#### 4. Intercept Traffic with HTTP Toolkit

- Use HTTP Toolkit to intercept traffic between your Android device and the DRM server when DRM content is accessed or played.
- HTTP Toolkit provides a user-friendly interface to view and analyze intercepted requests and responses.

#### 5. Extract Unencrypted Challenges

- Identify HTTP requests related to DRM challenges in HTTP Toolkit.
- Extract unencrypted challenge data from intercepted requests using HTTP Toolkit's inspection tools.
- Note down the necessary parameters or tokens that are part of the DRM challenge.

#### 6. Analyze and Use Data

- Once you have extracted the unencrypted challenge data, analyze it to understand the structure and content.
- Use this data for further research, analysis, or integration into your DRM extraction workflows.

### Example Workflow

1. **Start HTTP Toolkit:**
    - Open HTTP Toolkit and ensure interception is enabled for your device's network traffic.

2. **Run KeyDive:**
    - Execute KeyDive on your Android device, ensuring it intercepts DRM-related requests.

3. **Access DRM Content:**
    - Access DRM-protected content on your device that triggers DRM challenge requests.

4. **Intercept Requests:**
    - Use HTTP Toolkit to intercept HTTP requests related to DRM challenges.

5. **Extract Challenge Data:**
    - Inspect intercepted requests in HTTP Toolkit to extract unencrypted challenge data.

6. **Use Extracted Data:**
    - Use the extracted data with KeyDive by running:
      ```shell
      keydive --serial <DEVICE_ID> --challenge path/to/challenge
      ```
   Replace `path/to/challenge` with the actual path to the extracted challenge data file.

### Additional Tips

- **Using Frida Scripts for SSL Pinning Bypass:** If your Android device is rooted but encountering SSL pinning issues, consider using Frida scripts such as [Android SSL Pinning](https://codeshare.frida.re/@hyugogirubato/android-ssl-pinning/). These scripts are designed to bypass SSL certificate pinning implemented by applications, allowing tools like HTTP Toolkit to capture and analyze HTTPS traffic effectively.
- **Device ID Extraction Issues:** If KeyDive encounters difficulties extracting the device ID directly, consider these methods as a workaround when direct device ID extraction is not feasible or successful.

By integrating KeyDive with HTTP Toolkit, you can streamline the process of extracting unencrypted challenges from DRM-protected content on Android devices, facilitating research and analysis in digital rights management.