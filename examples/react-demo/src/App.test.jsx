import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from './App';

// Mock the ethers wallet import to prevent actual EIP-712/network operations
vi.mock('ethers', () => {
  return {
    HDNodeWallet: {
      fromPhrase: vi.fn().mockReturnValue({
        privateKey: '0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        address: '0xd8da6bf26964af9d7eed9e03e53415d37aa96045',
      }),
    },
  };
});

// Mock the WASM library to isolate UI state and interactions
vi.mock('kem-dem-wasm', () => {
  class MockKemDem {
    static encryptionDerivationPath() {
      return "m/44'/60'/0'/2147483647'/0";
    }
    generateKeypair() {
      return {
        publicKey: new Uint8Array([1, 2, 3]),
        secretKey: new Uint8Array([4, 5, 6]),
      };
    }
    deriveKeypairFromIkm() {
      return {
        publicKey: new Uint8Array([7, 8, 9]),
        secretKey: new Uint8Array([10, 11, 12]),
      };
    }
    deriveKeypairFromSignature() {
      return {
        publicKey: new Uint8Array([13, 14, 15]),
        secretKey: new Uint8Array([16, 17, 18]),
      };
    }
    encryptFields() {
      return {
        kemCiphertext: new Uint8Array([99, 99]),
        toObject: () => ({ kemCiphertext: new Uint8Array([99, 99]) }),
        fieldNames: () => ['ssn', 'dob'],
        getField: () => new Uint8Array([88, 88]),
      };
    }
    decryptFields() {
      return {
        ssn: '123-45-6789',
        dob: '1990-01-01',
      };
    }
  }

  const MockZkEncryptor = {
    generateKeypair: () => ({
      secretKey: '0x04b4c877627eb294fa24c6cc59a89fab5439c76e988bbda91d7ab0a9b189512c',
      publicKey: {
        x: '0x17e11f7a551369d058537d5a6c36f11b64696cbb9052edee99d1b3fd1e66a51b',
        y: '0x2a764ea29fa20359bcaddb14565501930f67420bdbff2aadf06b052848c753d3',
      },
    }),
    encrypt: () => '0xmocked_ciphertext',
    encryptAuthenticated: () => '0xmocked_auth_ciphertext',
    encryptWithDomains: () => '0xmocked_domain_ciphertext',
    encryptAuthenticatedWithDomains: () => '0xmocked_auth_domain_ciphertext',
    decrypt: () => ['0xcafe', '0xbeef'],
    decryptAuthenticated: () => ['0xcafe', '0xbeef'],
    decryptWithDomains: () => ['0xcafe', '0xbeef'],
    decryptAuthenticatedWithDomains: () => ['0xcafe', '0xbeef'],
  };

  class MockEncryptedPackage {
    constructor(kemCiphertext, encryptedFields) {
      this.kemCiphertext = kemCiphertext;
      this.encryptedFields = encryptedFields;
    }
  }

  return {
    default: vi.fn().mockResolvedValue({}),
    KemDem: MockKemDem,
    ZkEncryptor: MockZkEncryptor,
    EncryptedPackage: MockEncryptedPackage,
  };
});

describe('React KEM-DEM Demo Application', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the loading spinner initially', () => {
    render(<App />);
    expect(screen.getByText('Loading KEM-DEM WASM module...')).toBeDefined();
  });

  it('renders the main UI once WASM is initialized', async () => {
    render(<App />);

    // Wait for WASM initialization and state updates
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    expect(screen.getByText('1. Encryption Keypair Source')).toBeDefined();
    expect(screen.getByText('2. Fields to Encrypt')).toBeDefined();
    expect(screen.getByText('3. Encrypt / Decrypt')).toBeDefined();
  });

  it('allows generating a random keypair', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    const generateBtn = screen.getByRole('button', { name: 'Generate Random Keypair' });
    fireEvent.click(generateBtn);

    // Verify key display elements appear
    expect(screen.getByText('Derived Public Key (32 bytes)')).toBeDefined();
    expect(screen.getByText('Derived Secret Key (32 bytes)')).toBeDefined();
  });

  it('allows switching key derivation modes to BIP-32 seed path', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    const bip32Btn = screen.getByRole('button', { name: 'Seed/IKM (BIP-32)' });
    fireEvent.click(bip32Btn);

    expect(screen.getByText('Derivation Path')).toBeDefined();
    expect(screen.getByText('Auto-derived parameters')).toBeDefined();

    const deriveBtn = screen.getByRole('button', { name: 'Derive Deterministic Keypair' });
    fireEvent.click(deriveBtn);

    expect(screen.getByText('Derived Public Key (32 bytes)')).toBeDefined();
  });

  it('supports adding and removing payload fields', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    const addFieldBtn = screen.getByRole('button', { name: '+ Add Field' });
    fireEvent.click(addFieldBtn);

    const inputs = screen.getAllByPlaceholderText('Field name');
    expect(inputs.length).toBe(4); // 3 defaults + 1 new

    // Remove the last field
    const removeButtons = screen.getAllByTitle('Remove field');
    fireEvent.click(removeButtons[removeButtons.length - 1]);

    const finalInputs = screen.getAllByPlaceholderText('Field name');
    expect(finalInputs.length).toBe(3);
  });

  it('supports standard HPKE encrypt/decrypt roundtrip', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    // Generate keys first
    fireEvent.click(screen.getByRole('button', { name: 'Generate Random Keypair' }));

    // Click encrypt
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt Fields' }));

    // Verify encrypted package output tab is visible
    expect(screen.getByText('HPKE Encapsulated Key (32 bytes)')).toBeDefined();

    // Click decrypt
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt Fields' }));

    // Click on the decrypted tab
    fireEvent.click(screen.getByRole('button', { name: 'HPKE Decrypted' }));

    expect(screen.getByText('123-45-6789')).toBeDefined();
    expect(screen.getByText('1990-01-01')).toBeDefined();
  });

  it('supports ZK BabyJubJub authenticated encrypt/decrypt roundtrip', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    // Switch algorithm to ZK
    fireEvent.click(screen.getByRole('button', { name: 'ZK Encryption (BabyJubJub)' }));

    expect(screen.getByText('ZK Keypair (auto-generated)')).toBeDefined();

    // Click encrypt
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt Fields' }));

    // Check ZK Ciphertext tab is showing
    expect(screen.getByText('ZK Ciphertext (BabyJubJub KEM-DEM, authenticated)')).toBeDefined();

    // Click decrypt
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt ZK' }));

    // Verify decrypted text items are rendered
    expect(screen.getByText('ZK Decrypted Payload')).toBeDefined();
  });

  it('supports ZK BabyJubJub with custom domain separation settings', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('KEM-DEM WASM Demo')).toBeDefined();
    });

    // Switch algorithm to ZK
    fireEvent.click(screen.getByRole('button', { name: 'ZK Encryption (BabyJubJub)' }));

    // Click on "Enable Custom Domain Separation" checkbox
    const domainCheckbox = screen.getByLabelText('Enable Custom Domain Separation');
    fireEvent.click(domainCheckbox);

    // KEM/DEM inputs should become visible
    expect(screen.getByText('KEM Domain Separator (BE hex Fr254)')).toBeDefined();
    expect(screen.getByText('DEM Domain Separator (BE hex Fr254)')).toBeDefined();

    // Click encrypt
    fireEvent.click(screen.getByRole('button', { name: 'Encrypt Fields' }));

    // Click decrypt
    fireEvent.click(screen.getByRole('button', { name: 'Decrypt ZK' }));

    // Verify decrypted text items are rendered
    expect(screen.getByText('ZK Decrypted Payload')).toBeDefined();
  });
});
