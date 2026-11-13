<template>
  <view>
    <button @tap="locate">附近门店</button>
  </view>
</template>

<script setup>
import { request } from '../../utils/request'
uni.onNeedPrivacyAuthorization((resolve) => resolve({ event: 'agree' }))
function locate() {
  uni.getLocation({ type: 'gcj02', success: (r) => request('/stores?lat=' + r.latitude) })
  console.log('locate')
}
</script>
