const BASE_URL = 'http://api.example.com'
const DEV_URL = 'http://localhost:8080'
const LAN_URL = 'http://192.168.1.10:3000'
const SVG_NS = 'http://www.w3.org/2000/svg'
const IGNORED = 'http://legacy.example.com' // sec-check-ignore

export function request(path) {
  return uni.request({
    url: BASE_URL + path,
    sslVerify: false,
  })
}

export function getToken() {
  // 错误示范：小程序端直接调微信服务端接口
  return uni.request({ url: 'https://api.weixin.qq.com/cgi-bin/token' })
}
