/**
 * 加密工具父类
 */
export default abstract class Helper {
  protected _switchTool: boolean = true;
  protected tool: SubtleCrypto;
  constructor() {
    if (!crypto || !crypto.subtle) {
      throw new Error("您的浏览器不支持 crypto api...");
    }

    this.tool = crypto.subtle;
  }

  /** 工具初始化（包含密钥生成等操作） */
  abstract init(ops): Promise<this>;
  /** 加密 */
  abstract encrypt(
    content: string | ArrayBuffer,
    onProgress?: (progress: number) => void
  ): Promise<ArrayBuffer> | PromiseLike<ArrayBuffer>;
  /** 解密 */
  abstract decrypt(
    content: string | ArrayBuffer,
    onProgress?: (progress: number) => void
  ): Promise<ArrayBuffer> | PromiseLike<ArrayBuffer>;
  /** 设置开关 */
  public set switchTool(val: boolean) {
    this._switchTool = val;
  }
  /** 获取开关 */
  public get switchTool() {
    return this._switchTool;
  }
}
