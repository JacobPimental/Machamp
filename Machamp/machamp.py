import machamp_backend as M
import argparse
import yaml

class Application:


    def __init__(self, **kwargs):
        if not kwargs['quiet']:
            self.print_banner()
        self.machamp = M.Machamp(kwargs.get('file', None))
        if not kwargs['generate'] == None:
            self.generate_table(kwargs['generate'], kwargs['output'],
                                kwargs['quiet'])
        if not kwargs['rename'] == None:
            self.rename_functions(kwargs['rename'], kwargs['quiet'],
                                  kwargs['threshold'])

    def generate_table(self, exclude, output, quiet):
        table = self.machamp.form_machamp_table(exclude, quiet)
        if output:
            self.machamp.output_machamp_table(table, output)
        else:
            print(yaml.dump(table))

    def rename_functions(self, args, quiet, threshold):
        infile = args[0]
        exclude = []
        if len(args) > 1:
            exclude = args[1:]
        if not threshold:
            threshold = 80
        compare_to = self.machamp.read_machamp_file(infile)
        self.machamp.rename_functions(compare_to=compare_to, exclude=exclude,
                                      threshold=threshold)


    def print_banner(self):
        print('                 __."`. .-.                    ,-..__')
        print('              ,-.  \  |-| |               ,-"+\' ,"\'  `.')
        print('              \  \  \_\' `.\'             .\'  .|_.|_.,--\'.')
        print('               \.\'`"     `.              `-\' `.   .  _,\'.')
        print('                \_     `"""-.             ."--+\   \'"   |')
        print('                | `""+..`..,\'             `-._ |        |')
        print('               j     |                       \'.       _/.')
        print('              /   ,\' `.      _.----._          `"-.  \'   \'')
        print('             |   |     |   ,\'  ,.-"""`.           |  .    \'')
        print('    __       |   \'    /-._.  ,\'        `.         |   \    \'')
        print('   (  `.     `.     .\'    | /  _,.-----. \       j     .    \'')
        print('    `. |.  __  `,         |j ,\'\        `|"+---._|          ,')
        print(' .-"-|"\' \"  |   ". \'.    ||/d |_-""`.    /     ,\'.          )')
        print(' `._. |  \'.,.\'     \'  `  ,||_.-"      |  j     \'   `        .')
        print('."\'--:\' .  )        `.  (     _.-+    |  |                  |')
        print('`-,..\'  ` <_          `-.`..+"   \'   ./,  ._         |      |')
        print(' `.__|   |  `-._     _.-"`. |   /  ,\'j      `. `....\' ____..\'')
        print('   `-.,.\'    \  `. ,\'     ,-|_,\'  /  |        `.___,-\'   )')
        print('      `.      `.  Y       `-..__.\',-\'    __,.\'           \'')
        print('        `         \'   ,--.    |  /            `+""       `.')
        print('         `.       ,--+   \'  .-+-"  _,\'   ,--  /     \'.    |')
        print('           `-..   \     __,\'           .\'    /        `.  |')
        print('               `---)   |  ____,\'      ,....-\'           `,\'')
        print('                  \'                 ,\' _,-----.         /')
        print('                   `.____,.....___.\ _...______________/')
        print('                                  __\:+.`\'O O  O O  O |')
        print('                              ,-"\'  _,|:;|""""""""""""|')
        print('                            ,\'   ,-\'  `._/    _."  .`-|')
        print('                         .-"    \'      \    .\'      `.`.')
        print('                        :      .        \   |        / |')
        print('                         .      \.__   _,`-.|       /  |')
        print('                         `.      \  ""\'     `.         `....')
        print('                           .     |            \             `.')
        print('                          .\'   ,\'              \              |')
        print('                  ,------\'     `.               `-...._  \'"-.\'.')
        print('                 / ,\'"\'"`        |                  `--`._     `.')
        print('                 `"......---""--\'                         \       .')
        print('                                                           |       `.')
        print('                                                         (   -..     .')
        print('                                                          `"""\' `....\' mh')
        print()
        print('@@@@@@@@@@    @@@@@@    @@@@@@@  @@@  @@@   @@@@@@   @@@@@@@@@@   @@@@@@@  ')
        print('@@@@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@@@@  @@@@@@@@ ')
        print('@@! @@! @@!  @@!  @@@  !@@       @@!  @@@  @@!  @@@  @@! @@! @@!  @@!  @@@ ')
        print('!@! !@! !@!  !@!  @!@  !@!       !@!  @!@  !@!  @!@  !@! !@! !@!  !@!  @!@ ')
        print('@!! !!@ @!@  @!@!@!@!  !@!       @!@!@!@!  @!@!@!@!  @!! !!@ @!@  @!@@!@!  ')
        print('!@!   ! !@!  !!!@!!!!  !!!       !!!@!!!!  !!!@!!!!  !@!   ! !@!  !!@!!!   ')
        print('!!:     !!:  !!:  !!!  :!!       !!:  !!!  !!:  !!!  !!:     !!:  !!:      ')
        print(':!:     :!:  :!:  !:!  :!:       :!:  !:!  :!:  !:!  :!:     :!:  :!:      ')
        print(':::     ::   ::   :::   ::: :::  ::   :::  ::   :::  :::     ::    ::      ')
        print(' :      :     :   : :   :: :: :   :   : :   :   : :   :      :     :')
        print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    #parser.add_argument('-i', '--interactive', action='store_true',
    #                    help='Enable Interactive Mode')

    parser.add_argument('-f', '--file', help='The file to process',
                        default='')

    parser.add_argument('-t', '--threshold', type=int,
                        help=('Threshold for function comparison; ' +
                              'used with the rename function utility'))

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-g', '--generate', nargs='*',
                        metavar='EXCLUDE',
                        help=('Generate Machamp table, excluding functions in '
                              +'EXCLUDE')
                       )

    group.add_argument('-r', '--rename', nargs='+',
                        help=('Rename functions based on machamp table file'+
                              ' [INFILE], excluding functions in EXCLUDE'),
                        metavar=('INFILE', 'EXCLUDE'))

    parser.add_argument('-o', '--output',
                        help='Write output to file out-file')

    parser.add_argument('-q', '--quiet', action='store_true',
                        help='quiet output')

    args = parser.parse_args()
    print(vars(args))
    app = Application(**vars(args))
