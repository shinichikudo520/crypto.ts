/**
 * 合并 ArrayBuffer
 * @param bufferArr ArrayBuffer 数据数组
 */
export function concatArrayBuffer(bufferArr: ArrayBuffer[]): ArrayBuffer {
  const len = bufferArr.reduce((len, buffer) => len + buffer.byteLength, 0);
  const u8arr = new Uint8Array(len);
  let start = 0;
  for (const buffer of bufferArr) {
    u8arr.set(new Uint8Array(buffer), start);
    start += buffer.byteLength;
  }
  return u8arr.buffer;
}

/**
 * str ==> ArrayBuffer
 * @param str 需要转化的 string 类型数据
 * @param bufType 需要转化的 ArrayBuffer 数据类型
 */
export function str2buffer1(
  str: string,
  bufType: BUFFER_TYPE = BUFFER_TYPE.UINT8
): ArrayBuffer {
  let buf: ArrayBuffer;
  let bufView: Uint8Array | Uint16Array;
  switch (bufType) {
    case BUFFER_TYPE.UINT8: {
      buf = new ArrayBuffer(str.length);
      bufView = new Uint8Array(buf);
      break;
    }
    case BUFFER_TYPE.UINT16: {
      buf = new ArrayBuffer(str.length);
      bufView = new Uint16Array(buf);
      break;
    }
    default: {
      console.warn("bufType参数错误，使用默认 uint8");
      buf = new ArrayBuffer(str.length);
      bufView = new Uint8Array(buf);
      break;
    }
  }

  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
}

/**
 * ArrayBuffer => string
 * @param buffer 需要转化的 ArrayBuffer 类型数据
 * @param bufType 需要转化的 ArrayBuffer 数据类型
 */
export function buffer2str1(
  buffer: ArrayBuffer,
  bufType: BUFFER_TYPE = BUFFER_TYPE.UINT8
): string {
  let arr;
  switch (bufType) {
    case BUFFER_TYPE.UINT8: {
      arr = new Uint8Array(buffer);
      break;
    }
    case BUFFER_TYPE.UINT16: {
      arr = new Uint16Array(buffer);
      break;
    }
    default: {
      console.warn("bufType参数错误，使用默认 uint8");
      arr = new Uint8Array(buffer);
      break;
    }
  }
  return String.fromCharCode.apply(null, arr);
}

/**
 * string => arrayBuffer
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function str2buffer(str: string): ArrayBuffer {
  let enc = new TextEncoder();
  return enc.encode(str);
}
/**
 * arrayBuffer => string
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function buffer2str(
  buffer: ArrayBuffer,
  label: string = "utf-8"
): string {
  const dec = new TextDecoder(label);
  return dec.decode(buffer);
}
/**
 * arrayBuffer => hex(十六进制)
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function buf2hex(buffer: ArrayBuffer): string {
  return Array.prototype.map
    .call(new Uint8Array(buffer), (x) => ("00" + x.toString(16)).slice(-2))
    .join("");
}
/**
 *  hex(十六进制) => a rrayBuffer
 * @param {string} hex 十六进制字符串
 * @returns {ArrayBuffer}
 */
export function hex2buf(hex: string): ArrayBuffer {
  const arr = new Uint8Array(
    hex.match(/[\da-f]{2}/gi)?.map(function (h) {
      return parseInt(h, 16);
    }) || []
  );
  return arr.buffer;
}
/**
 * binary(二进制) => string
 * @param {string} binary 二进制字符串
 * @returns {string}
 */
export function binary2str(binary: string = ""): string {
  const arr = binary.split(" ");
  const str = arr
    .map((part) => {
      return String.fromCharCode(parseInt(part, 2));
    })
    .join("");
  return str;
}
