import argon2, { argon2d } from 'argon2';
import * as crypto from 'crypto';
import { Encoding } from 'crypto';
import { Buffer } from 'buffer';

export class CryptoUtil {
  static argon2timeCost = 100;
  static aesKeyBytes = 32;
  static aesIVBytes = 16;
  static aes256Ctr = 'aes-256-ctr';
  static aes256Ecb = 'aes-256-ecb';

  static encodeAESEcb(data: string, key: string, inputEncoding: Encoding | undefined = 'utf-8', outputEncoding: Encoding = 'hex'): string {
    const keyBuffer = CryptoUtil.getKeyBuffer(key);
    const cipher = crypto.createCipheriv(CryptoUtil.aes256Ecb, keyBuffer, null);
    let encryptedData = cipher.update(data, inputEncoding, outputEncoding);
    encryptedData += cipher.final(outputEncoding);
    return encryptedData;
  }

  static decodeAESEcb(encryptedData: string, key: string, inputEncoding: Encoding | undefined = 'hex', outputEncoding: Encoding = 'utf-8'): string {
    const keyBuffer = CryptoUtil.getKeyBuffer(key);
    const cipher = crypto.createDecipheriv(CryptoUtil.aes256Ecb, keyBuffer, null);
    let decryptedData = cipher.update(encryptedData, inputEncoding, outputEncoding);
    decryptedData += cipher.final(outputEncoding);
    return decryptedData;
  }

  static encodeAESCtr(data: string, key: string, IV: string, inputEncoding: Encoding | undefined = 'utf-8', outputEncoding: Encoding = 'hex'): string {
    const keyBuffer = CryptoUtil.getKeyBuffer(key);
    const IVBuffer = CryptoUtil.getIVBuffer(IV);
    const cipher = crypto.createCipheriv(CryptoUtil.aes256Ctr, keyBuffer, IVBuffer);
    let encryptedData = cipher.update(data, inputEncoding, outputEncoding);
    encryptedData += cipher.final(outputEncoding);
    return encryptedData;
  }

  static decodeAESCtr(encryptedData: string, key: string, IV: string, inputEncoding: Encoding | undefined = 'hex', outputEncoding: Encoding = 'utf-8'): string {
    const keyBuffer = CryptoUtil.getKeyBuffer(key);
    const IVBuffer = CryptoUtil.getIVBuffer(IV);
    const cipher = crypto.createDecipheriv(CryptoUtil.aes256Ctr, keyBuffer, IVBuffer);
    let decryptedData = cipher.update(encryptedData, inputEncoding, outputEncoding);
    decryptedData += cipher.final(outputEncoding);
    return decryptedData;
  }

  static getHash(data: string | Buffer, algorithm?: string, encoding?: 'base64' | 'base64url' | 'hex'): string {
    algorithm = algorithm ? algorithm : 'sha256';
    encoding = encoding ? encoding : 'hex';
    const hash = crypto.createHash(algorithm);
    hash.update(data);
    return hash.digest(encoding);
  }

  static getKeyBuffer(key: string): Buffer {
    const additionalBuffer = Buffer.from([1, ...new Array(CryptoUtil.aesKeyBytes - 1).fill(0)]);
    return Buffer.concat([Buffer.from(key), additionalBuffer], CryptoUtil.aesKeyBytes);
  }

  static getIVBuffer(IV: string): Buffer {
    const additionalBuffer = Buffer.from([1, ...new Array(CryptoUtil.aesIVBytes - 1).fill(0)]);
    return Buffer.concat([Buffer.from(IV), additionalBuffer], CryptoUtil.aesIVBytes);
  }

  static async getHashWithArgon2d(data: string): Promise<string> {
    let result: string;
    try {
      result = await argon2.hash(data, { timeCost: CryptoUtil.argon2timeCost, type: argon2d });
    } catch (error) {
      throw new Error('Error using Argon2d');
    }
    return result;
  }

  static async checkHashWithArgon2d(data: string, dataHash: string): Promise<boolean> {
    let result: boolean;
    try {
      result = await argon2.verify(dataHash, data, { timeCost: CryptoUtil.argon2timeCost, type: argon2d });
    } catch (error) {
      throw new Error('Error using Argon2d');
    }
    return result;
  }
}
