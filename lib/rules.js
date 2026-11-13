'use strict';

// 规则元数据。每条规则都写明依据；没有官方依据的「卫生类」规则标 basis: 'hygiene'。
const SRC = {
  wxNetwork: 'https://developers.weixin.qq.com/miniprogram/dev/framework/ability/network.html',
  wxAppJson: 'https://developers.weixin.qq.com/miniprogram/dev/reference/configuration/app.html',
  wxPrivacy: 'https://developers.weixin.qq.com/miniprogram/dev/framework/user-privacy/PrivacyAuthorize.html',
  wxPrivacyIntro: 'https://developers.weixin.qq.com/miniprogram/dev/framework/user-privacy/miniprogram-intro.html',
  wxEnableDebug: 'https://developers.weixin.qq.com/miniprogram/dev/api/base/debug/wx.setEnableDebug.html',
  payApiV3Key: 'https://pay.weixin.qq.com/doc/v3/merchant/4012072195',
  payLeak: 'https://pay.weixin.qq.com/doc/v3/merchant/4012073693',
  uniManifest: 'https://uniapp.dcloud.net.cn/collocation/manifest.html',
  uniRequest: 'https://uniapp.dcloud.net.cn/api/request/request.html',
};

const RULES = {
  SEC001: { name: 'hardcoded-secret', title: '前端代码里写死了 AppSecret / secret 类密钥', sources: [SRC.wxNetwork] },
  SEC002: { name: 'hardcoded-pay-key', title: '前端代码里写死了微信支付密钥（APIv3 / APIv2 / 商户 key）', sources: [SRC.payApiV3Key, SRC.payLeak] },
  SEC003: { name: 'private-key-block', title: '项目里出现 PEM 私钥内容', sources: [SRC.payLeak] },
  SEC004: { name: 'cert-file', title: '项目里放了证书 / 私钥文件', sources: [SRC.payLeak] },
  SEC005: { name: 'env-secret', title: '.env 文件里有密钥类变量', sources: [SRC.wxNetwork, SRC.payLeak] },
  SEC006: { name: 'wx-server-api-in-client', title: '小程序端直接调用 api.weixin.qq.com', sources: [SRC.wxNetwork] },
  NET001: { name: 'plain-http', title: '代码里有 http:// / ws:// 地址', sources: [SRC.wxNetwork] },
  NET002: { name: 'ssl-verify-false', title: 'uni.request 关闭了 sslVerify', sources: [SRC.uniRequest] },
  NET003: { name: 'url-check-off', title: 'mp-weixin.setting.urlCheck 关闭了域名校验', sources: [SRC.uniManifest, SRC.wxNetwork] },
  MAN001: { name: 'manifest', title: 'manifest.json 缺失或无法解析', sources: [SRC.uniManifest] },
  MAN002: { name: 'mp-weixin-appid', title: 'mp-weixin.appid 为空', sources: [SRC.uniManifest] },
  MAN003: { name: 'permission-desc', title: 'mp-weixin.permission 用途说明缺失或超长', sources: [SRC.wxAppJson, SRC.uniManifest] },
  MAN004: { name: 'required-private-infos-missing', title: '用了地理位置接口但没在 requiredPrivateInfos 声明', sources: [SRC.wxAppJson] },
  MAN005: { name: 'required-private-infos-extra', title: 'requiredPrivateInfos 里有未知值或代码里没用到的接口', sources: [SRC.wxAppJson] },
  MAN006: { name: 'location-permission-missing', title: '用了精确定位接口但没配置 scope.userLocation 用途说明', sources: [SRC.uniManifest, SRC.wxAppJson] },
  MAN007: { name: 'use-privacy-check-obsolete', title: '__usePrivacyCheck__ 已无作用', sources: [SRC.wxPrivacy] },
  PRV001: { name: 'privacy-api-used', title: '用到了隐私接口，需在《用户隐私保护指引》声明', sources: [SRC.wxPrivacyIntro, SRC.wxPrivacy] },
  DBG001: { name: 'console-log', title: '源码里的 console.log / console.debug', sources: [], basis: 'hygiene' },
  DBG002: { name: 'vconsole-eruda', title: '引入了 vConsole / eruda 调试面板', sources: [], basis: 'hygiene' },
  DBG003: { name: 'set-enable-debug', title: '代码里打开了 setEnableDebug（对正式版也生效）', sources: [SRC.wxEnableDebug] },
};

// requiredPrivateInfos 支持的 8 个地理位置接口（微信 app.json 文档）
const LOCATION_PRIVATE_INFOS = [
  'getFuzzyLocation', 'getLocation', 'onLocationChange', 'startLocationUpdate',
  'startLocationUpdateBackground', 'chooseLocation', 'choosePoi', 'chooseAddress',
];

// 《小程序用户隐私保护指引内容介绍》里「处理的信息 ↔ 接口」对照（节选，只列 API 形式能静态识别的）
const PRIVACY_API_GROUPS = [
  { info: '位置信息', apis: ['getLocation', 'startLocationUpdate', 'startLocationUpdateBackground', 'getFuzzyLocation'], scopes: ['userLocation', 'userLocationBackground', 'userFuzzyLocation'] },
  { info: '选择的位置信息', apis: ['choosePoi', 'chooseLocation'] },
  { info: '地址', apis: ['chooseAddress'] },
  { info: '发票信息', apis: ['chooseInvoiceTitle', 'chooseInvoice'] },
  { info: '微信运动步数', apis: ['getWeRunData'], scopes: ['werun'] },
  { info: '手机号', openTypes: ['getPhoneNumber', 'getRealtimePhoneNumber'] },
  { info: '昵称、头像', openTypes: ['chooseAvatar'], nicknameInput: true },
  { info: '车牌号', apis: ['chooseLicensePlate'] },
  { info: '选中的照片或视频', apis: ['chooseImage', 'chooseMedia', 'chooseVideo'] },
  { info: '选中的文件', apis: ['chooseMessageFile'] },
  { info: '麦克风', apis: ['startRecord', 'joinVoIPChat', 'getRecorderManager'], scopes: ['record'] },
  { info: '摄像头', apis: ['createVKSession'], scopes: ['camera'], tags: ['camera'] },
  { info: '蓝牙', apis: ['openBluetoothAdapter', 'createBLEPeripheralServer'], scopes: ['bluetooth'] },
  { info: '相册（仅写入）', apis: ['saveImageToPhotosAlbum', 'saveVideoToPhotosAlbum'], scopes: ['writePhotosAlbum'] },
  { info: '通讯录（仅写入）', apis: ['addPhoneContact'], scopes: ['addPhoneContact'] },
  { info: '日历（仅写入）', apis: ['addPhoneRepeatCalendar', 'addPhoneCalendar'], scopes: ['addPhoneCalendar'] },
  { info: '加速传感器', apis: ['startAccelerometer'] },
  { info: '磁场传感器', apis: ['startCompass'] },
  { info: '方向传感器', apis: ['startDeviceMotionListening'] },
  { info: '陀螺仪传感器', apis: ['startGyroscope'] },
  { info: '剪切板', apis: ['setClipboardData', 'getClipboardData'] },
];

module.exports = { RULES, SRC, LOCATION_PRIVATE_INFOS, PRIVACY_API_GROUPS };
