<template>
	<div class="card">
		<h2>Privacy Tools</h2>
		<label><input type="checkbox" v-model="antiKeylogger"/> Anti-Keylogger</label>
		<label><input type="checkbox" v-model="antiClip"/> Anti-Clipjacking</label>
		<label><input type="checkbox" v-model="camMic"/> Webcam/Mic Lock</label>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const antiKeylogger = ref(true);
const antiClip = ref(true);
const camMic = ref(true);
</script>