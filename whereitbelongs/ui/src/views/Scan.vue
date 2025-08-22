<template>
	<div class="card">
		<h2>Scan</h2>
		<div style="display:flex; gap:8px; align-items:center;">
			<input v-model="path" placeholder="Path to scan" style="width:380px;"/>
			<button @click="runScan">Scan</button>
		</div>
	</div>
	<div class="card" style="margin-top:12px;">
		<h3>Detections</h3>
		<ul>
			<li v-for="d in detections" :key="d.path">{{ d.kind }} — {{ d.path }}</li>
		</ul>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const path = ref<string>(".");
const detections = ref<{kind:string; path:string}[]>([]);
function runScan(){
	// IPC integration will be added in Tauri backend
	detections.value.push({ kind: 'Heuristic', path: path.value + '/example' });
}
</script>