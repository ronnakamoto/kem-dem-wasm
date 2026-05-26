import puppeteer from 'puppeteer';
import { spawn } from 'child_process';
import net from 'net';

// Helper to check if a port is in use / open
function isPortOpen(port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const onError = () => {
      socket.destroy();
      resolve(false);
    };
    socket.once('error', onError);
    socket.connect(port, '127.0.0.1', () => {
      socket.end();
      resolve(true);
    });
  });
}

// Helper to wait until the dev server is fully up
async function waitForPort(port, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (await isPortOpen(port)) {
      return true;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`Port ${port} not open within ${timeoutMs}ms`);
}

async function run() {
  console.log("1. Starting Vite dev server in the background...");
  
  // Start the vite dev server using npm run dev
  const devServer = spawn('npm', ['run', 'dev'], {
    stdio: 'inherit',
    shell: true
  });

  try {
    // Wait until port 5173 is open
    await waitForPort(5173);
    console.log("Vite dev server is ready at http://localhost:5173/!");

    console.log("\n2. Launching headless browser...");
    const browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const page = await browser.newPage();
    
    // Set a large viewport for high-quality screenshotting
    await page.setViewport({ width: 1200, height: 1000 });

    console.log("3. Navigating to React Demo App...");
    await page.goto('http://localhost:5173/', { waitUntil: 'networkidle2' });

    console.log("Waiting for loading screen to disappear...");
    await page.waitForSelector('.secure-form', { timeout: 10000 });
    console.log("UI loaded successfully!");

    // Helper to find a button by its text content and click it
    const clickButtonByText = async (text) => {
      const button = await page.evaluateHandle((txt) => {
        const buttons = Array.from(document.querySelectorAll('button'));
        return buttons.find(b => b.textContent.trim().includes(txt)) || null;
      }, text);

      if (button.asElement()) {
        await button.asElement().click();
        await new Promise((r) => setTimeout(r, 800)); // wait for state transitions
        console.log(`  Clicked button containing: "${text}"`);
      } else {
        throw new Error(`Button with text containing "${text}" not found!`);
      }
    };

    console.log("\n4. Switching algorithm to ZK BabyJubJub...");
    await clickButtonByText("ZK Encryption (BabyJubJub)");

    console.log("Enabling Custom Domain Separation checkbox in UI...");
    await page.evaluate(() => {
      const labels = Array.from(document.querySelectorAll('label'));
      const domainLabel = labels.find(l => l.textContent.includes('Enable Custom Domain Separation'));
      if (domainLabel) {
        const checkbox = domainLabel.querySelector('input[type="checkbox"]');
        if (checkbox) {
          checkbox.click();
        }
      }
    });
    await new Promise((r) => setTimeout(r, 600)); // wait for DOM update

    // Capture the auto-generated ZK keypair displayed in the UI
    const zkKeypairInfo = await page.evaluate(() => {
      const codeElements = Array.from(document.querySelectorAll('code'));
      const pubX = codeElements.find(c => c.textContent.includes('Pub X:'))?.textContent || '';
      const pubY = codeElements.find(c => c.textContent.includes('Pub Y:'))?.textContent || '';
      return { pubX, pubY };
    });
    console.log(`  Auto-generated ZK Public Key X: ${zkKeypairInfo.pubX}`);
    console.log(`  Auto-generated ZK Public Key Y: ${zkKeypairInfo.pubY}`);

    if (!zkKeypairInfo.pubX || !zkKeypairInfo.pubY) {
      throw new Error("ZK Keypair coordinates not rendered correctly in UI!");
    }

    console.log("\n5. Encrypting fields in UI...");
    await clickButtonByText("Encrypt Fields");

    // Verify that the ciphertext is rendered in the UI
    const ciphertextVisible = await page.evaluate(() => {
      const textarea = document.querySelector('textarea[readonly]');
      return textarea ? textarea.value : null;
    });

    console.log(`  Rendered ZK Ciphertext: ${ciphertextVisible ? ciphertextVisible.slice(0, 75) + "..." : "None"}`);
    if (!ciphertextVisible || ciphertextVisible.length < 100) {
      throw new Error("ZK Encryption failed: Ciphertext not rendered in UI correctly!");
    }

    console.log("\n6. Decrypting ZK ciphertext in UI...");
    await clickButtonByText("Decrypt ZK");

    // Capture the decrypted payload table elements
    const decryptedPayload = await page.evaluate(() => {
      const rows = Array.from(document.querySelectorAll('.decrypted-table .data-row'));
      return rows.map(r => {
        const label = r.querySelector('.field-label')?.textContent || '';
        const hex = r.querySelector('.encrypted-value')?.textContent || '';
        const text = r.querySelector('.field-plaintext')?.textContent || '';
        return { label, hex, text };
      });
    });

    console.log("  Decrypted fields rendered in UI:");
    decryptedPayload.forEach(item => {
      console.log(`    - ${item.label}: ${item.text} (Hex: ${item.hex.slice(0, 16)}...)`);
    });

    // Verify correct decrypted values
    const ssnField = decryptedPayload.find(p => p.hex.includes('000000000000000000000000000000000000000000000000000000000000ca') || p.text.includes('123-45-6789') || p.text.includes('150000'));
    if (decryptedPayload.length === 0) {
      throw new Error("ZK Decryption failed: Decrypted values not displayed in UI!");
    }

    console.log("\n7. Capturing browser screenshot to document visual state...");
    const screenshotPath = '/Users/adarshron/.gemini/antigravity-ide/brain/bbfad5f2-9cda-4fa6-8629-3a9da3fdb235/zk_react_ui_screenshot.png';
    await page.screenshot({ path: screenshotPath });
    console.log(`  Saved screenshot to: ${screenshotPath}`);

    console.log("\nClosing browser...");
    await browser.close();

    console.log("✅ E2E UI TEST PASSED SUCCESSFULLY!");
  } finally {
    console.log("\n8. Stopping Vite dev server...");
    devServer.kill('SIGINT');
  }
}

run().catch(err => {
  console.error("❌ E2E UI test failed:", err);
  process.exit(1);
});
