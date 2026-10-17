<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query"
import { useRouteQuery } from "@vueuse/router"
import { TriangleAlert } from "@lucide/vue"
import { computed } from "vue"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import QueryState from "@/core/components/QueryState.vue"

import KeyboxTab from "../components/KeyboxTab.vue"
import ImportTab from "../components/ImportTab.vue"
import ProfileTab from "../components/ProfileTab.vue"
import ProvisionTab from "../components/ProvisionTab.vue"
import VerifyTab from "../components/VerifyTab.vue"
import { useRkpI18n } from "../i18n"
import { useRkpStore } from "../store"

const { t } = useRkpI18n()
const store = useRkpStore()
const tab = useRouteQuery("tab", "import", { mode: "replace" })
const experimental = computed(() => ["profile", "provision", "keybox"].includes(tab.value))

const loading = useQuery({
  queryKey: ["rkp.profile"],
  queryFn: async () => {
    await store.load()
    return true
  },
  staleTime: Number.POSITIVE_INFINITY,
  enabled: experimental,
})

const tabs = ["import", "profile", "provision", "keybox", "verify"] as const
</script>

<template>
  <div class="flex flex-col gap-4 p-4 pt-0">
    <QueryState
      :loading="experimental && loading.isPending.value"
      :error="experimental ? loading.error.value : null"
      @retry="loading.refetch()"
    >
      <Tabs v-model="tab" class="gap-6">
        <TabsList class="h-auto w-full flex-wrap">
          <TabsTrigger v-for="name in tabs" :key="name" :value="name">
            {{ t(`tabs.${name}`) }}
          </TabsTrigger>
        </TabsList>
        <Alert v-if="experimental">
          <TriangleAlert />
          <AlertTitle>{{ t("experimental.title") }}</AlertTitle>
          <AlertDescription>{{ t("experimental.description") }}</AlertDescription>
        </Alert>
        <TabsContent value="import"><ImportTab /></TabsContent>
        <TabsContent value="profile"><ProfileTab /></TabsContent>
        <TabsContent value="provision"><ProvisionTab /></TabsContent>
        <TabsContent value="keybox"><KeyboxTab /></TabsContent>
        <TabsContent value="verify"><VerifyTab /></TabsContent>
      </Tabs>
    </QueryState>
  </div>
</template>
