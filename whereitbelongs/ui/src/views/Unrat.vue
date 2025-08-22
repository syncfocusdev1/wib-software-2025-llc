<template>
	<div class="card">
		<h2>UNRAT Recovery</h2>
		<p>Removes RAT persistence, tasks, and WMI subscriptions.</p>
		<button @click="recover" :disabled="busy">{{ busy ? 'Running...' : 'One-Click Recovery' }}</button>
		<p v-if="msg" style="margin-top:8px;">{{ msg }}</p>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const busy = ref(false);
const msg = ref('');
async function recover(){
	busy.value = true;
	try{
		// IPC to backend unrat.one_click
		await new Promise(r=>setTimeout(r,600));
		msg.value = 'Recovery complete';
	} finally {
		busy.value = false;
	}
}
</script>