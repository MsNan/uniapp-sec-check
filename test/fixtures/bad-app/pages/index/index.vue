<template>
  <view class="page">
    <!-- <button open-type="chooseAvatar">注释里的按钮不算</button> -->
    <button open-type="getPhoneNumber" @getphonenumber="onPhone">手机号登录</button>
    <text>访问 http://help.example.com 了解更多</text>
  </view>
</template>

<script setup>
// console.log('注释里的不算')
// http://commented.example.com
function pick() {
  uni.getLocation({ type: 'gcj02' })
  uni.chooseImage({ count: 1 })
  console.log('picked')
}
function onPhone(e) {
  console.log(e)
}
</script>
