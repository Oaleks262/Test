class ScanQueue {
  constructor(concurrency = 3) {
    this.concurrency = concurrency;
    this.running = 0;
    this.queue = [];
  }

  add(task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ task, resolve, reject });
      this._process();
    });
  }

  _process() {
    if (this.running >= this.concurrency || this.queue.length === 0) return;
    this.running++;
    const { task, resolve, reject } = this.queue.shift();
    Promise.resolve().then(() => task()).then(resolve, reject).finally(() => {
      this.running--;
      this._process();
    });
  }

  get size() { return this.queue.length; }
  get active() { return this.running; }
}

module.exports = new ScanQueue(3);
