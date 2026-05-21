import { HDNodeWallet } from 'ethers';

const phrase = "test test test test test test test test test test test junk";
const path = "m/44'/60'/0'/2147483647'/0";

try {
  // Try passing the path directly to fromPhrase
  const wallet1 = HDNodeWallet.fromPhrase(phrase, "", path);
  console.log("Success with fromPhrase:", wallet1.address);
} catch (e) {
  console.error("Error with fromPhrase:", e.message);
}

try {
  import('ethers').then(({ Mnemonic }) => {
    const mnemonic = Mnemonic.fromPhrase(phrase);
    const wallet2 = HDNodeWallet.fromMnemonic(mnemonic, path);
    console.log("Success with fromMnemonic:", wallet2.address);
  });
} catch (e) {
  console.error("Error with fromMnemonic:", e.message);
}
