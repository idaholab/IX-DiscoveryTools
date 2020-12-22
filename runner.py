class plugin_runner:
    def __init__(self, args, stix_loader):
        self.args = args
        self.stix_loader = stix_loader

        if args.network:
            self.run()
            
    def run(self):
        """
        here we need to figure out the plugins we 
        need to run from the args then run them
        Each will likely take the stix_loader as an argument,
        along with all the other args
        """
        pass