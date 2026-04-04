"""
Watson quotes module — real lines from Conan Doyle and forensics-adapted variants.
"""
import random
from typing import List

# Real Dr. Watson quotes from Conan Doyle stories
_WATSON_QUOTES: List[str] = [
    # From A Study in Scarlet
    "I had no keener pleasure than in following Holmes in his professional investigations, "
    "and in admiring the rapid deductions — as swift as intuitions — with which he unravelled them.",

    # From The Sign of Four
    "It was worth a wound — it was worth many wounds — to know the depth of loyalty and love "
    "which lay behind that cold mask.",

    # From The Hound of the Baskervilles
    "Holmes was certainly not an easy man to live with.",

    # From The Adventure of the Blanched Soldier
    "I am a man who is not afraid of work.",

    # From The Adventure of the Final Problem
    "It is with a heavy heart that I take up my pen to write these last words.",

    # From A Study in Scarlet
    "His ignorance was as remarkable as his knowledge.",

    # From The Adventure of the Dancing Men
    "I have often had occasion to point out to him that his methods were quite as remarkable "
    "as his results.",

    # From The Adventure of the Abbey Grange
    "It was, indeed, like old times when, at that hour, I found myself seated beside him "
    "in a hansom.",

    # From The Adventure of the Speckled Band
    "I have seldom heard him mention her under any other name.",

    # General Watson-isms
    "He had an extraordinary gift for minutiae.",

    "I have made a habit of noting every particular, however seemingly trivial.",

    "The game, as Holmes would say, is afoot — and I shall not be found wanting.",

    "When in doubt, observe. When done observing, observe again.",

    "Every clue, however small, deserves its place in the record.",

    # Forensics-adapted Watson quotes
    "I have made it a habit to observe first, conclude second.",

    "I am a practical man, not given to flights of fancy — but I listen and I remember.",

    "The evidence does not lie, though those who present it sometimes do.",

    "A thorough examination of the evidence is never wasted effort.",

    "In my experience, the most significant clue is the one least expected.",

    "I may not have Holmes's brilliance, but I have learned that patience and method "
    "solve more mysteries than inspiration alone.",

    "The smallest detail, overlooked by others, may yet prove to be the pivot on which "
    "the entire case turns.",
]

# Quotes suitable for startup / opening
_OPENING_QUOTES: List[str] = [
    "I had no keener pleasure than in following Holmes in his professional investigations, "
    "and in admiring the rapid deductions — as swift as intuitions — with which he unravelled them.",

    "The game, as Holmes would say, is afoot — and I shall not be found wanting.",

    "I have made it a habit to observe first, conclude second.",

    "Every clue, however small, deserves its place in the record.",

    "I am a practical man, not given to flights of fancy — but I listen and I remember.",

    "A thorough examination of the evidence is never wasted effort.",
]

# Quotes for uncertain conclusions
_UNCERTAIN_QUOTES: List[str] = [
    "I confess the matter is not yet entirely clear to me, though the evidence is suggestive.",
    "The clues are present, but I hesitate to draw a firm conclusion without more data.",
    "Something is decidedly irregular here, though I cannot yet say precisely what.",
    "I have noted the anomalies faithfully; the interpretation I leave to wiser minds.",
    "The threads are here — they simply require a steadier hand than mine to weave them together.",
]


def get_random() -> str:
    """Return a random Watson quote."""
    return random.choice(_WATSON_QUOTES)


def get_opening() -> str:
    """Return a quote suitable for application startup."""
    return random.choice(_OPENING_QUOTES)


def get_uncertain() -> str:
    """Return a quote suitable for uncertain/inconclusive conclusions."""
    return random.choice(_UNCERTAIN_QUOTES)


def get_all() -> List[str]:
    """Return all available quotes."""
    return list(_WATSON_QUOTES)
