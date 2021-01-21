import {Command, flags} from '@oclif/command'

import {readFile} from 'fs'
import {promisify} from 'util'
import {createPkeyFromMnemonic, decryptString, isSeedValid} from './vault'

const readFilePromise = promisify(readFile)

interface Account {
  id: string;
  name: string;
  content: string;
  category?: any;
  encryptContent?: boolean;
}

const getPkeyWithMnemonic = async (mnemonic: string) => {
  if (!isSeedValid(mnemonic)) {
    throw new Error('mnemonic invalid')
  }
  const key = await createPkeyFromMnemonic(mnemonic)
  return key.privKey
}

class Mylegacycli extends Command {
  static description = 'describe the command here'

  static flags = {
    version: flags.version({char: 'v'}),
    help: flags.help({char: 'h'}),
    file: flags.string({
      char: 'f',
      description: 'file to decrypt',
      multiple: false,
      required: true,
    }),
    mnemonic: flags.string({
      char: 'm',
      description: 'mnemonic used to decrypt',
      multiple: false,
      required: true,
    })
  }

  async run() {
    const {flags} = this.parse(Mylegacycli)

    if (!flags.file) {
      this.error('please pass your encrypted json file path to --file')
      return
    }

    if (!flags.mnemonic) {
      this.error('please pass your mnemonic to --mnemonic')
    }

    const rawContent = await readFilePromise(flags.file, 'utf-8')
    let content: Account[]
    try {
      content = JSON.parse(rawContent)
    } catch (error) {
      this.error('fail to parse file content')
      return
    }
    const pkey = await getPkeyWithMnemonic(flags.mnemonic.split('').join(' '))
    const decryptedAccounts = content.map(a => {
      if (a.encryptContent) {
        const decryptedContent = decryptString(pkey, JSON.parse(a.content))
        if (!decryptedContent) {
          this.error('fail to decrypt, check your mnemonic')
        }
        return {
          ...a,
          content: decryptedContent,
        }
      }
      return a
    })
    this.log(JSON.stringify(decryptedAccounts))
  }
}

export = Mylegacycli
