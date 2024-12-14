import { test, expect } from "@playwright/test";
import path from "path";

test("initial page load", async ({ page }) => {
    await page.goto("http://localhost:8080/");

    await expect(page).toHaveTitle("PKCS#10 Parser");

    await expect(page.getByTestId("filename")).toHaveText("No file selected");
});

test("upload rsa-csr.pem", async ({ page }) => {
    await page.goto("http://localhost:8080/");

    const fileChooserPromise = page.waitForEvent("filechooser");

    await page.getByRole("button", { name: "Pick a file" }).click();

    const fileChooser = await fileChooserPromise;

    await fileChooser.setFiles(path.join(process.cwd(), "../src/test/resources/rsa-csr.pem"));

    await page.waitForResponse("http://localhost:8080/api/v1/csr");

    await expect(page.getByTestId("filename")).toHaveText("rsa-csr.pem");

    await expect(page.getByTestId("signature-algorithm")).toContainText("SHA256WITHRSA");
    await expect(page.getByTestId("public-key-algorithm")).toContainText("RSA");
    await expect(page.getByTestId("rsa-key-length")).toContainText("2048");
    await expect(page.getByTestId("common-name")).toHaveText("www.example.com");
    await expect(page.getByTestId("country")).toHaveText("AU");
    await expect(page.getByTestId("locality")).toHaveText("Some-City");
    await expect(page.getByTestId("state-or-province")).toHaveText("Some-State");
    await expect(page.getByTestId("org-name")).toHaveText("Internet Widgits Pty Ltd");
    await expect(page.getByTestId("org-unit")).toHaveText("Company-Section");
    await expect(page.getByTestId("email-address")).toHaveText("some@company.com");
});

test("upload rsa-csr-san.pem", async ({ page }) => {
    await page.goto("http://localhost:8080/");

    const fileChooserPromise = page.waitForEvent("filechooser");

    await page.getByRole("button", { name: "Pick a file" }).click();

    const fileChooser = await fileChooserPromise;

    await fileChooser.setFiles(path.join(process.cwd(), "../src/test/resources/rsa-csr-san.pem"));

    await page.waitForResponse("http://localhost:8080/api/v1/csr");

    await expect(page.getByTestId("filename")).toHaveText("rsa-csr-san.pem");

    await expect(page.getByTestId("signature-algorithm")).toContainText("SHA256WITHRSA");
    await expect(page.getByTestId("public-key-algorithm")).toContainText("RSA");
    await expect(page.getByTestId("rsa-key-length")).toContainText("4096");
    await expect(page.getByTestId("common-name")).toHaveText("example.com");
    await expect(page.getByTestId("country")).toHaveText("DE");
    await expect(page.getByTestId("locality")).not.toBeAttached();
    await expect(page.getByTestId("state-or-province")).toHaveText("NRW");
    await expect(page.getByTestId("org-name")).toHaveText("Internet Widgits Pty Ltd");
    await expect(page.getByTestId("org-unit")).not.toBeAttached();
    await expect(page.getByTestId("email-address")).not.toBeAttached();
    await expect(page.getByTestId("san")).toHaveText("DNS: test.com, DNS: test.de");
});

test("upload some-file", async ({ page }) => {
    await page.goto("http://localhost:8080/");

    const fileChooserPromise = page.waitForEvent("filechooser");

    await page.getByRole("button", { name: "Pick a file" }).click();

    const fileChooser = await fileChooserPromise;

    await fileChooser.setFiles(path.join(process.cwd(), "../src/test/resources/some-file"));

    await page.waitForResponse("http://localhost:8080/api/v1/csr");

    await expect(page.getByTestId("filename")).toHaveText("some-file");

    await expect(page.getByTestId("error-message")).toHaveText(
        "File is not a valid Certificate Signing Request",
    );
    await expect(page.getByTestId("signature-algorithm")).not.toBeAttached();
    await expect(page.getByTestId("public-key-algorithm")).not.toBeAttached();
    await expect(page.getByTestId("rsa-key-length")).not.toBeAttached();
    await expect(page.getByTestId("common-name")).not.toBeAttached();
    await expect(page.getByTestId("country")).not.toBeAttached();
    await expect(page.getByTestId("locality")).not.toBeAttached();
    await expect(page.getByTestId("state-or-province")).not.toBeAttached();
    await expect(page.getByTestId("org-name")).not.toBeAttached();
    await expect(page.getByTestId("org-unit")).not.toBeAttached();
    await expect(page.getByTestId("email-address")).not.toBeAttached();
    await expect(page.getByTestId("san")).not.toBeAttached();
});
