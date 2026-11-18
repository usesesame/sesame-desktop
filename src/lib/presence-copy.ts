export type PresenceIntent = 'reveal' | 'copy' | 'autotype' | 'enable-icons' | 'request-kit' | 'issue-kit' | 'reveal-field' | 'copy-field' | 'check-password' | 'unlock-note' | 'clear-activity' | 'shorten-activity'

export const presenceCopy: Record<PresenceIntent, { heading: string; description: string; action: string }> = {
  reveal: {
    heading: 'Show this password',
    description: 'Sesame asks for your master password again before it reveals a saved password.',
    action: 'Show password',
  },
  copy: {
    heading: 'Copy this password',
    description: 'Sesame asks for your master password again before it copies a saved password. The password stays hidden.',
    action: 'Copy password',
  },
  'reveal-field': {
    heading: 'Show this value',
    description: 'Sesame asks for your master password again before it reveals a saved secret.',
    action: 'Show value',
  },
  'copy-field': {
    heading: 'Copy this value',
    description: 'Sesame asks for your master password again before it copies a saved secret. The value stays hidden.',
    action: 'Copy value',
  },
  'unlock-note': {
    heading: 'Remove the note lock',
    description: 'Sesame asks for your master password again before it removes the lock from a note, because the lock is what keeps the note hidden.',
    action: 'Remove lock',
  },
  'clear-activity': {
    heading: 'Clear the activity record',
    description: 'Sesame asks for your master password again before it clears the activity record, because the record is how you can see what left the vault.',
    action: 'Clear record',
  },
  'shorten-activity': {
    heading: 'Keep activity for less time',
    description: 'Sesame asks for your master password again before it removes older entries from the activity record, because the record is how you can see what left the vault.',
    action: 'Remove older entries',
  },
  'check-password': {
    heading: 'Check this password',
    description: 'Sesame asks for your master password again before it checks a saved password against known breaches. Only the first five characters of its hash leave this device.',
    action: 'Check password',
  },
  autotype: {
    heading: 'Type this login',
    description: 'Sesame asks for your master password again before it types a saved login into another window. Typing starts after a short countdown so you can switch to the field.',
    action: 'Start typing',
  },
  'enable-icons': {
    heading: 'Turn on website icons',
    description: 'Sesame asks for your master password before it turns on website icon downloads for this device.',
    action: 'Turn on',
  },
  'request-kit': {
    heading: 'Request a new recovery kit',
    description: 'Enter your master password. The new kit is ready in 72 hours, measured with servers on the internet, two of which must agree, rather than this computer\'s clock. Sesame shows a warning on every unlock until then so a request you did not make can be cancelled.',
    action: 'Request kit',
  },
  'issue-kit': {
    heading: 'Get your new recovery kit',
    description: 'Enter your master password. Sesame gives the vault a new encryption key and a new kit. Your master password stays the same. The old kit stops opening this vault, and PIN and Windows Hello unlock turn off until you set them up again. Backups made before today still open with the old kit.',
    action: 'Get kit',
  },
}
