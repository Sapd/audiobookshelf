<template>
  <div class="w-full py-6">
    <div class="flex items-center mb-4">
      <p class="text-lg mb-0 font-semibold">Episodes</p>
      <div class="flex-grow" />
      <template v-if="isSelectionMode">
        <ui-tooltip :text="`Mark as ${selectedIsFinished ? 'Not Finished' : 'Finished'}`" direction="bottom">
          <ui-read-icon-btn :disabled="processing" :is-read="selectedIsFinished" @click="toggleBatchFinished" class="mx-1.5" />
        </ui-tooltip>
        <ui-btn color="error" :disabled="processing" small class="h-9" @click="removeSelectedEpisodes">Remove {{ selectedEpisodes.length }} episode{{ selectedEpisodes.length > 1 ? 's' : '' }}</ui-btn>
        <ui-btn :disabled="processing" small class="ml-2 h-9" @click="clearSelected">Cancel</ui-btn>
      </template>
      <controls-episode-sort-select v-else v-model="sortKey" :descending.sync="sortDesc" class="w-36 sm:w-44 md:w-48 h-9 ml-1 sm:ml-4" />
    </div>
    <p v-if="!episodes.length" class="py-4 text-center text-lg">No Episodes</p>
    <template v-for="episode in episodesSorted">
      <tables-podcast-episode-table-row ref="episodeRow" :key="episode.id" :episode="episode" :library-item-id="libraryItem.id" :selection-mode="isSelectionMode" class="item" @play="playEpisode" @remove="removeEpisode" @edit="editEpisode" @view="viewEpisode" @selected="episodeSelected" />
    </template>

    <modals-podcast-remove-episode v-model="showPodcastRemoveModal" @input="removeEpisodeModalToggled" :library-item="libraryItem" :episodes="episodesToRemove" @clearSelected="clearSelected" />
  </div>
</template>

<script>
export default {
  props: {
    libraryItem: {
      type: Object,
      default: () => {}
    }
  },
  data() {
    return {
      episodesCopy: [],
      sortKey: 'publishedAt',
      sortDesc: true,
      selectedEpisode: null,
      showPodcastRemoveModal: false,
      selectedEpisodes: [],
      episodesToRemove: [],
      processing: false
    }
  },
  watch: {
    libraryItem() {
      this.init()
    }
  },
  computed: {
    isSelectionMode() {
      return this.selectedEpisodes.length > 0
    },
    userCanUpdate() {
      return this.$store.getters['user/getUserCanUpdate']
    },
    media() {
      return this.libraryItem.media || {}
    },
    mediaMetadata() {
      return this.media.metadata || {}
    },
    episodes() {
      return this.media.episodes || []
    },
    episodesSorted() {
      return this.episodesCopy.sort((a, b) => {
        if (this.sortDesc) {
          return String(b[this.sortKey]).localeCompare(String(a[this.sortKey]), undefined, { numeric: true, sensitivity: 'base' })
        }
        return String(a[this.sortKey]).localeCompare(String(b[this.sortKey]), undefined, { numeric: true, sensitivity: 'base' })
      })
    },
    selectedIsFinished() {
      // Find an item that is not finished, if none then all items finished
      return !this.selectedEpisodes.find((episode) => {
        var itemProgress = this.$store.getters['user/getUserMediaProgress'](this.libraryItem.id, episode.id)
        return !itemProgress || !itemProgress.isFinished
      })
    }
  },
  methods: {
    toggleBatchFinished() {
      this.processing = true
      var newIsFinished = !this.selectedIsFinished
      var updateProgressPayloads = this.selectedEpisodes.map((episode) => {
        return {
          libraryItemId: this.libraryItem.id,
          episodeId: episode.id,
          isFinished: newIsFinished
        }
      })

      this.$axios
        .patch(`/api/me/progress/batch/update`, updateProgressPayloads)
        .then(() => {
          this.$toast.success('Batch update success!')
          this.processing = false
          this.clearSelected()
        })
        .catch((error) => {
          this.$toast.error('Batch update failed')
          console.error('Failed to batch update read/not read', error)
          this.processing = false
        })
    },
    removeEpisodeModalToggled(val) {
      if (!val) this.episodesToRemove = []
    },
    clearSelected() {
      const episodeRows = this.$refs.episodeRow
      if (episodeRows && episodeRows.length) {
        for (const epRow of episodeRows) {
          if (epRow) epRow.isSelected = false
        }
      }
      this.selectedEpisodes = []
    },
    removeSelectedEpisodes() {
      this.episodesToRemove = this.selectedEpisodes
      this.showPodcastRemoveModal = true
    },
    episodeSelected({ isSelected, episode }) {
      if (isSelected) {
        this.selectedEpisodes.push(episode)
      } else {
        this.selectedEpisodes = this.selectedEpisodes.filter((ep) => ep.id !== episode.id)
      }
    },
    playEpisode(episode) {
      const queueItems = []

      const episodesInListeningOrder = this.episodesCopy.map((ep) => ({ ...ep })).sort((a, b) => String(a.publishedAt).localeCompare(String(b.publishedAt), undefined, { numeric: true, sensitivity: 'base' }))
      const episodeIndex = episodesInListeningOrder.findIndex((e) => e.id === episode.id)
      for (let i = episodeIndex; i < episodesInListeningOrder.length; i++) {
        const episode = episodesInListeningOrder[i]
        const podcastProgress = this.$store.getters['user/getUserMediaProgress'](this.libraryItem.id, episode.id)
        if (!podcastProgress || !podcastProgress.isFinished) {
          queueItems.push({
            libraryItemId: this.libraryItem.id,
            episodeId: episode.id,
            title: episode.title,
            subtitle: this.mediaMetadata.title,
            caption: episode.publishedAt ? `Published ${this.$formatDate(episode.publishedAt, 'MMM do, yyyy')}` : 'Unknown publish date',
            duration: episode.audioFile.duration || null,
            coverPath: this.media.coverPath || null
          })
        }
      }

      this.$eventBus.$emit('play-item', {
        libraryItemId: this.libraryItem.id,
        episodeId: episode.id,
        queueItems
      })
    },
    removeEpisode(episode) {
      this.episodesToRemove = [episode]
      this.showPodcastRemoveModal = true
    },
    editEpisode(episode) {
      this.$store.commit('setSelectedLibraryItem', this.libraryItem)
      this.$store.commit('globals/setSelectedEpisode', episode)
      this.$store.commit('globals/setShowEditPodcastEpisodeModal', true)
    },
    viewEpisode(episode) {
      this.$store.commit('setSelectedLibraryItem', this.libraryItem)
      this.$store.commit('globals/setSelectedEpisode', episode)
      this.$store.commit('globals/setShowViewPodcastEpisodeModal', true)
    },
    init() {
      this.episodesCopy = this.episodes.map((ep) => ({ ...ep }))
    }
  },
  mounted() {
    this.init()
  }
}
</script>

<style>
.episode-item {
  transition: all 0.4s ease;
}

.episode-enter-from,
.episode-leave-to {
  opacity: 0;
  transform: translateX(30px);
}

.episode-leave-active {
  position: absolute;
}
</style>