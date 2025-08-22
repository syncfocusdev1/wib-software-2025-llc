<template>
	<div class="card">
		<h2>System Status</h2>
		<ul>
			<li>Realtime Protection: {{ realtime ? 'On' : 'Off' }}</li>
			<li>Firewall: {{ firewall ? 'On' : 'Off' }}</li>
		</ul>
	</div>
	<div class="card" style="margin-top:12px;">
		<h3>Live Logs</h3>
		<pre style="max-height:240px; overflow:auto;">{{ logs.join('\n') }}</pre>
	</div>
</template>
<script setup lang="ts">
import { ref } from 'vue';
const realtime = ref(true);
const firewall = ref(true);
const logs = ref<string[]>(["WIB initialized", "Realtime protection active"]);
</script>